"""Release-blocking tenant lifecycle and cross-tenant IDOR tests."""

from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path

import httpx
import pytest

from ai_agent_lab.api import create_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.auth import (
    APIKeyAuthenticator,
    APIKeyManager,
    AuthenticationError,
    Principal,
    Role,
    StaticAuthenticator,
)
from ai_agent_lab.domain import Tenant, TenantAccessError, TenantContext
from ai_agent_lab.storage import FileArtifactStore, create_schema, make_engine, session_factory
from ai_agent_lab.storage.repositories import TenantRepository

PEPPER = "tenant-isolation-fixture-pepper-at-least-32-bytes"


class Client:
    def __init__(self, app) -> None:
        self._app = app

    def request(self, method: str, path: str, **kwargs):
        async def send():
            transport = httpx.ASGITransport(app=self._app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self.request("POST", path, **kwargs)


def _stack(tmp_path: Path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'tenant.db').as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        tenants = TenantRepository(session)
        tenants.add(Tenant(id="tenant_a", name="Tenant A"))
        tenants.add(Tenant(id="tenant_b", name="Tenant B"))
    service = LabApplicationService(
        sessions, FileArtifactStore(tmp_path / "artifacts")
    )
    return engine, sessions, service


def _client(service: LabApplicationService, tenant_id: str) -> Client:
    principal = Principal(
        f"admin_{tenant_id}", tenant_id, frozenset({Role.ADMIN}), "local"
    )
    return Client(
        create_app(service=service, authenticator=StaticAuthenticator(principal))
    )


def _project_and_run(client: Client, *, idempotency_key: str = "tenant-fixture-key"):
    project_response = client.post(
        "/v1/projects", json={"name": "Tenant Project"}
    )
    assert project_response.status_code == 201, project_response.text
    project = project_response.json()
    run_response = client.post(
        "/v1/runs",
        json={
            "project_id": project["id"],
            "suite_version": "built-in-v1",
            "seed": 1,
            "idempotency_key": idempotency_key,
        },
    )
    assert run_response.status_code == 202, run_response.text
    return project, run_response.json()


def test_tenant_context_is_frozen_and_cannot_be_client_data() -> None:
    context = TenantContext("tenant_a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.tenant_id = "tenant_b"
    with pytest.raises(ValueError, match="tenant_id"):
        TenantContext(" ")


def test_tenant_status_transition_is_optimistic_and_validated(tmp_path: Path) -> None:
    engine, sessions, _ = _stack(tmp_path)
    with sessions.begin() as session:
        repository = TenantRepository(session)
        assert repository.set_status("tenant_a", "suspended", expected_version=1)
        assert not repository.set_status("tenant_a", "active", expected_version=1)
        with pytest.raises(ValueError, match="active or suspended"):
            repository.set_status("tenant_a", "deleted", expected_version=2)
    with sessions() as session:
        tenant = TenantRepository(session).get("tenant_a")
        assert tenant is not None and tenant.status == "suspended"
        assert tenant.version == 2
    engine.dispose()


def test_application_service_rejects_missing_and_suspended_tenants(tmp_path: Path) -> None:
    engine, sessions, service = _stack(tmp_path)
    with sessions.begin() as session:
        TenantRepository(session).set_status(
            "tenant_a", "suspended", expected_version=1
        )
    for context in (TenantContext("tenant_a"), TenantContext("missing")):
        with pytest.raises(TenantAccessError, match="tenant access denied"):
            service.list_projects(context)
        with pytest.raises(TenantAccessError, match="tenant access denied"):
            service.process_next(context, owner="worker")
    engine.dispose()


def test_suspended_and_missing_tenant_api_responses_are_indistinguishable(
    tmp_path: Path,
) -> None:
    engine, sessions, service = _stack(tmp_path)
    with sessions.begin() as session:
        TenantRepository(session).set_status(
            "tenant_a", "suspended", expected_version=1
        )
    suspended = _client(service, "tenant_a").get("/v1/projects")
    missing = _client(service, "missing").get("/v1/projects")
    assert suspended.status_code == missing.status_code == 403
    assert suspended.json()["error"]["code"] == "tenant_access_denied"
    assert missing.json()["error"]["code"] == "tenant_access_denied"
    assert "suspended" not in suspended.text.lower()
    assert "missing" not in missing.text.lower()
    engine.dispose()


def test_api_key_authentication_stops_when_tenant_is_suspended(tmp_path: Path) -> None:
    engine, sessions, _ = _stack(tmp_path)
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
    )
    with sessions.begin() as session:
        TenantRepository(session).set_status(
            "tenant_a", "suspended", expected_version=1
        )
    with pytest.raises(AuthenticationError, match="invalid credentials"):
        APIKeyAuthenticator(sessions, PEPPER).authenticate(f"Bearer {issued.token}")
    engine.dispose()


def test_api_key_issuance_rejects_missing_or_suspended_tenant(tmp_path: Path) -> None:
    engine, sessions, _ = _stack(tmp_path)
    manager = APIKeyManager(sessions, PEPPER)
    with pytest.raises(ValueError, match="tenant is unavailable"):
        manager.issue(
            tenant_id="missing", roles=[Role.VIEWER], created_by="admin"
        )
    with sessions.begin() as session:
        TenantRepository(session).set_status(
            "tenant_a", "suspended", expected_version=1
        )
    with pytest.raises(ValueError, match="tenant is unavailable"):
        manager.issue(
            tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
        )
    engine.dispose()


def test_cross_tenant_project_and_run_ids_are_not_usable(tmp_path: Path) -> None:
    engine, _, service = _stack(tmp_path)
    tenant_a = _client(service, "tenant_a")
    tenant_b = _client(service, "tenant_b")
    project, run = _project_and_run(tenant_a)
    assert tenant_b.get("/v1/projects").json() == []
    response = tenant_b.post(
        "/v1/runs",
        json={
            "project_id": project["id"],
            "suite_version": "built-in-v1",
            "seed": 1,
            "idempotency_key": "tenant-b-foreign-project",
        },
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "project_not_found"
    assert project["id"] not in response.text
    assert tenant_b.get(f"/v1/runs/{run['id']}").status_code == 404
    engine.dispose()


def test_cross_tenant_cancel_is_same_as_random_missing_id(tmp_path: Path) -> None:
    engine, _, service = _stack(tmp_path)
    tenant_a = _client(service, "tenant_a")
    tenant_b = _client(service, "tenant_b")
    _, run = _project_and_run(tenant_a)
    foreign = tenant_b.post(f"/v1/runs/{run['id']}/cancel")
    random = tenant_b.post("/v1/runs/run_does_not_exist/cancel")
    assert foreign.status_code == random.status_code == 409
    assert foreign.json()["error"]["code"] == random.json()["error"]["code"]
    assert run["id"] not in foreign.text
    assert tenant_a.get(f"/v1/runs/{run['id']}").json()["status"] == "queued"
    engine.dispose()


def test_cross_tenant_completed_reports_are_not_downloadable(tmp_path: Path) -> None:
    engine, _, service = _stack(tmp_path)
    tenant_a = _client(service, "tenant_a")
    tenant_b = _client(service, "tenant_b")
    _, run = _project_and_run(tenant_a)
    completed = service.process_next(TenantContext("tenant_a"), owner="worker")
    assert completed is not None and completed.status.value == "completed"
    for format_name in ("json", "markdown"):
        foreign = tenant_b.get(f"/v1/runs/{run['id']}/reports/{format_name}")
        random = tenant_b.get(
            f"/v1/runs/run_does_not_exist/reports/{format_name}"
        )
        assert foreign.status_code == random.status_code == 404
        assert foreign.json()["error"]["code"] == "report_not_found"
        assert run["id"] not in foreign.text
    engine.dispose()


def test_same_idempotency_key_is_isolated_per_tenant(tmp_path: Path) -> None:
    engine, _, service = _stack(tmp_path)
    _, run_a = _project_and_run(
        _client(service, "tenant_a"), idempotency_key="shared-idempotency-key"
    )
    _, run_b = _project_and_run(
        _client(service, "tenant_b"), idempotency_key="shared-idempotency-key"
    )
    assert run_a["id"] != run_b["id"]
    engine.dispose()


def test_worker_claim_never_crosses_tenant_context(tmp_path: Path) -> None:
    engine, _, service = _stack(tmp_path)
    _, run_a = _project_and_run(_client(service, "tenant_a"))
    assert service.process_next(TenantContext("tenant_b"), owner="worker_b") is None
    assert _client(service, "tenant_a").get(
        f"/v1/runs/{run_a['id']}"
    ).json()["status"] == "queued"
    engine.dispose()
