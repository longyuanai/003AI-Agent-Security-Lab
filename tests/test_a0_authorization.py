"""A0 negative cases using owned SQLite tenants and in-process ASGI only."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab.api import create_app
from ai_agent_lab.application import (
    AuthorizedLabApplicationService,
    LabApplicationService,
)
from ai_agent_lab.application import service as service_module
from ai_agent_lab.auth import (
    APIKeyAuthenticator,
    APIKeyManager,
    AuthorizationError,
    Principal,
    Role,
    StaticAuthenticator,
)
from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark
from ai_agent_lab.domain import RunStatus, Tenant, TenantAccessError, TenantContext
from ai_agent_lab.storage import (
    FileArtifactStore,
    create_schema,
    make_engine,
    session_factory,
)
from ai_agent_lab.storage.models import ReportArtifactRow
from ai_agent_lab.storage.repositories import TenantRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository

PEPPER = "a0-synthetic-pepper-at-least-32-bytes-only"
OPERATIONS = ("create_project", "list_projects", "create_run", "get_run", "cancel_run", "read_report")
DENIED = [
    (role, operation)
    for role, operations in (
        (Role.VIEWER, ("create_project", "create_run", "cancel_run")),
        (Role.OPERATOR, ("create_project",)),
        (Role.AUDITOR, OPERATIONS),
    )
    for operation in operations
]


@dataclass
class Stack:
    sessions: sessionmaker[Session]
    service: LabApplicationService
    artifacts: FileArtifactStore
    artifact_root: Path
    project: str
    run: str

    def suspend(self) -> None:
        with self.sessions.begin() as session:
            assert TenantRepository(session).set_status("tenant_a", "suspended", expected_version=1)


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    engine = make_engine(f"sqlite:///{(tmp_path / 'a0.db').as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        for tenant_id in ("tenant_a", "tenant_b"):
            TenantRepository(session).add(Tenant(id=tenant_id, name=tenant_id))
    artifact_root = tmp_path / "artifacts"
    artifacts = FileArtifactStore(artifact_root)
    service = LabApplicationService(sessions, artifacts)
    context = TenantContext("tenant_a")
    project = service.create_project(context, name="Owned fixture", created_by="a0")
    run, _ = service.create_run(
        context, project_id=project.id, suite_version="built-in-v1", seed=1,
        idempotency_key="a0-owned-run",
    )
    try:
        yield Stack(sessions, service, artifacts, artifact_root, project.id, run.id)
    finally:
        engine.dispose()


def request(app: FastAPI, stack: Stack, operation: str, **kwargs: Any) -> httpx.Response:
    routes: dict[str, tuple[str, str, dict[str, object] | None]] = {
        "create_project": ("POST", "/v1/projects", {"name": "Second fixture"}),
        "list_projects": ("GET", "/v1/projects", None),
        "create_run": ("POST", "/v1/runs", {
            "project_id": stack.project, "idempotency_key": "a0-another-run",
        }),
        "get_run": ("GET", f"/v1/runs/{stack.run}", None),
        "cancel_run": ("POST", f"/v1/runs/{stack.run}/cancel", None),
        "read_report": ("GET", f"/v1/runs/{stack.run}/reports/json", None),
    }
    method, path, body = routes[operation]
    body = kwargs.pop("json", body)

    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://a0.test",
        ) as client:
            return await client.request(method, path, json=body, **kwargs)

    return asyncio.run(send())


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("credential", ("missing", "tampered", "revoked"))
def test_every_resource_rejects_invalid_authentication(
    stack: Stack, operation: str, credential: str,
) -> None:
    manager = APIKeyManager(stack.sessions, PEPPER)
    issued = manager.issue(tenant_id="tenant_a", roles=[Role.ADMIN], created_by="a0")
    token = issued.token
    if credential == "revoked":
        assert manager.revoke(issued.key_id)
    elif credential == "tampered":
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
    app = create_app(service=stack.service, authenticator=APIKeyAuthenticator(stack.sessions, PEPPER))
    response = request(app, stack, operation, headers={} if credential == "missing" else {
        "Authorization": f"Bearer {token}",
    })
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"
    assert response.headers["www-authenticate"] == "Bearer"
    assert token not in response.text and stack.project not in response.text
    unchanged = stack.service.get_run(TenantContext("tenant_a"), stack.run)
    assert unchanged is not None and unchanged.status is RunStatus.QUEUED


@pytest.mark.parametrize("role,operation", DENIED)
def test_http_role_denial_for_every_forbidden_operation(
    stack: Stack, role: Role, operation: str,
) -> None:
    principal = Principal("a0", "tenant_a", frozenset({role}), "local")
    response = request(create_app(
        service=stack.service, authenticator=StaticAuthenticator(principal),
    ), stack, operation)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


@pytest.mark.parametrize("role,operation", DENIED)
def test_service_role_denial_happens_before_delegation(role: Role, operation: str) -> None:
    raw = Mock(spec=LabApplicationService)
    service = AuthorizedLabApplicationService(raw)
    principal = Principal("a0", "tenant_a", frozenset({role}), "local")
    arguments: dict[str, dict[str, object]] = {
        "create_project": {"name": "denied"}, "list_projects": {},
        "create_run": {"project_id": "p", "suite_version": "v", "seed": 1, "idempotency_key": "k"},
        "get_run": {"run_id": "r"}, "cancel_run": {"run_id": "r"},
        "read_report": {"run_id": "r", "format_name": "json"},
    }
    with pytest.raises(AuthorizationError, match="permission denied"):
        getattr(service, operation)(principal, **arguments[operation])
    assert raw.mock_calls == []


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("tenant_id", ("tenant_a", "missing"))
def test_verified_identity_still_requires_an_active_tenant(
    stack: Stack, operation: str, tenant_id: str,
) -> None:
    stack.suspend()
    # Simulate an already verified OIDC identity, not an IdP integration test.
    principal = Principal("a0", tenant_id, frozenset({Role.ADMIN}), "oidc")
    response = request(create_app(
        service=stack.service, authenticator=StaticAuthenticator(principal),
    ), stack, operation)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "tenant_access_denied"
    error = response.json()["error"]
    assert error["message"] == "Tenant access is denied"
    assert error["details"] == {}
    assert set(error) == {"code", "message", "request_id", "details"}
    assert stack.run not in response.text


def test_api_key_tenant_cannot_be_overridden_by_header_or_query(stack: Stack) -> None:
    token = APIKeyManager(stack.sessions, PEPPER).issue(
        tenant_id="tenant_b", roles=[Role.ADMIN], created_by="a0",
    ).token
    app = create_app(service=stack.service, authenticator=APIKeyAuthenticator(stack.sessions, PEPPER))
    response = request(app, stack, "get_run", headers={
        "Authorization": f"Bearer {token}", "X-Tenant-ID": "tenant_a",
    }, params={"tenant_id": "tenant_a"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "run_not_found"


def test_run_body_cannot_supply_tenant_context(stack: Stack) -> None:
    principal = Principal("a0", "tenant_a", frozenset({Role.ADMIN}), "local")
    response = request(create_app(
        service=stack.service, authenticator=StaticAuthenticator(principal),
    ), stack, "create_run", json={
        "project_id": stack.project, "tenant_id": "tenant_b",
        "idempotency_key": "a0-body-forgery",
    })
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_denied_request_does_not_log_bearer_secret(
    stack: Stack, caplog: pytest.LogCaptureFixture,
) -> None:
    token = APIKeyManager(stack.sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="a0",
    ).token
    app = create_app(service=stack.service, authenticator=APIKeyAuthenticator(stack.sessions, PEPPER))
    with caplog.at_level("INFO", logger="ai_agent_lab.api"):
        response = request(app, stack, "cancel_run", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert any(record.getMessage() == "http_request" for record in caplog.records)
    log_data = str([record.__dict__ for record in caplog.records])
    assert token not in log_data and token.rsplit(".", 1)[1] not in log_data


@pytest.mark.parametrize("phase", ("evaluation", "artifact_write"))
def test_worker_suspension_discards_reports_and_keeps_other_tenant_untouched(
    stack: Stack, phase: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_b = TenantContext("tenant_b")
    project_b = stack.service.create_project(context_b, name="B fixture", created_by="a0")
    run_b, _ = stack.service.create_run(
        context_b, project_id=project_b.id, suite_version="built-in-v1", seed=2,
        idempotency_key="a0-owned-run",  # Same key, different tenant.
    )
    if phase == "evaluation":
        def suspend_after_evaluation(*args: Any, **kwargs: Any) -> Any:
            result = evaluate_task_benchmark(*args, **kwargs)
            stack.suspend()
            return result

        monkeypatch.setattr(service_module, "evaluate_task_benchmark", suspend_after_evaluation)
    else:
        put = stack.artifacts.put

        def suspend_after_write(key: str, data: bytes) -> tuple[int, str]:
            result = put(key, data)
            if key.endswith(".md"):
                stack.suspend()
            return result

        monkeypatch.setattr(stack.artifacts, "put", suspend_after_write)
    with pytest.raises(TenantAccessError):
        stack.service.process_next(TenantContext("tenant_a"), owner="a0-worker")
    with stack.sessions() as session:
        run = EvaluationRunRepository(session, TenantContext("tenant_a")).get(stack.run)
        assert run is not None and run.status is RunStatus.FAILED
        assert session.scalars(select(ReportArtifactRow)).all() == []
    assert not [p for p in stack.artifact_root.rglob("*") if p.is_file()]
    assert stack.service.get_run(context_b, run_b.id) == run_b


def test_worker_claim_cannot_heartbeat_or_transition_through_other_tenant(stack: Stack) -> None:
    now = datetime.now(UTC)
    with stack.sessions.begin() as session:
        repo_a = EvaluationRunRepository(session, TenantContext("tenant_a"))
        claim = repo_a.claim_next(owner="same-worker-name", now=now)
        assert claim is not None
        repo_b = EvaluationRunRepository(session, TenantContext("tenant_b"))
        assert not repo_b.heartbeat(claim, now=now)
        assert not repo_b.transition(claim, RunStatus.RUNNING, now=now)
        current = repo_a.get(stack.run)
        assert current is not None and current.status is RunStatus.PREPARING
