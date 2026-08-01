"""M2 API -> durable worker -> evidence/report end-to-end tests."""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import urllib.request
from pathlib import Path

import httpx
import uvicorn

from ai_agent_lab.api import create_app
from ai_agent_lab.api.server import create_server_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.domain import Tenant, TenantContext
from ai_agent_lab.storage import FileArtifactStore, create_schema, make_engine, session_factory
from ai_agent_lab.storage.repositories import TenantRepository


class ASGIClient:
    def __init__(self, app) -> None:
        self._app = app

    def request(self, method: str, path: str, **kwargs):
        async def send():
            transport = httpx.ASGITransport(
                app=self._app, raise_app_exceptions=False
            )
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
    database = tmp_path / "commercial.db"
    engine = make_engine(f"sqlite:///{database.as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        repository = TenantRepository(session)
        repository.add(Tenant(id="tenant_a", name="Tenant A"))
        repository.add(Tenant(id="tenant_b", name="Tenant B"))
    artifacts = FileArtifactStore(tmp_path / "artifacts")
    service = LabApplicationService(sessions, artifacts)
    context = TenantContext("tenant_a")
    app = create_app(service=service, tenant_context=context)
    return engine, sessions, artifacts, service, context, ASGIClient(app)


def _create_project_and_run(client: ASGIClient):
    project_response = client.post(
        "/v1/projects",
        json={"name": "Authorized Benchmark", "target_policy": {"network": "deny"}},
    )
    assert project_response.status_code == 201, project_response.text
    project = project_response.json()
    run_response = client.post(
        "/v1/runs",
        json={
            "project_id": project["id"],
            "suite_version": "built-in-v1",
            "seed": 2026,
            "idempotency_key": "fixture-idempotency-2026",
        },
    )
    assert run_response.status_code == 202, run_response.text
    return project, run_response.json()


def test_full_api_worker_report_flow(tmp_path: Path) -> None:
    engine, _, _, service, context, client = _stack(tmp_path)
    project, run = _create_project_and_run(client)
    assert run["status"] == "queued"
    completed = service.process_next(context, owner="worker_e2e")
    assert completed is not None and completed.status.value == "completed"
    run_response = client.get(f"/v1/runs/{run['id']}")
    assert run_response.json()["status"] == "completed"
    assert run_response.json()["attempt"] == 1
    assert client.get("/v1/projects").json()[0]["id"] == project["id"]
    engine.dispose()


def test_e2e_reports_are_downloadable_and_privacy_safe(tmp_path: Path) -> None:
    engine, _, _, service, context, client = _stack(tmp_path)
    _, run = _create_project_and_run(client)
    service.process_next(context, owner="worker_e2e")
    json_report = client.get(f"/v1/runs/{run['id']}/reports/json")
    markdown = client.get(f"/v1/runs/{run['id']}/reports/markdown")
    assert json_report.status_code == 200
    assert markdown.status_code == 200
    assert json_report.json()["summary"]["total"] == 10
    assert "AI Agent Security Benchmark Report" in markdown.text
    combined = (json_report.text + markdown.text).lower()
    for forbidden in (
        "user_input",
        "input_text",
        "raw_prompt",
        "conversation_history",
        "authorization",
        "api_key",
    ):
        assert forbidden not in combined
    engine.dispose()


def test_run_creation_is_idempotent_through_api(tmp_path: Path) -> None:
    engine, _, _, _, _, client = _stack(tmp_path)
    project, first = _create_project_and_run(client)
    second = client.post(
        "/v1/runs",
        json={
            "project_id": project["id"],
            "suite_version": "changed-but-ignored-on-replay",
            "seed": 999,
            "idempotency_key": "fixture-idempotency-2026",
        },
    )
    assert second.status_code == 202
    assert second.json()["id"] == first["id"]
    assert second.json()["seed"] == 2026
    engine.dispose()


def test_single_tenant_context_never_accepts_client_tenant_id(tmp_path: Path) -> None:
    engine, _, _, _, _, client = _stack(tmp_path)
    response = client.post(
        "/v1/projects",
        json={"name": "Project", "tenant_id": "tenant_b"},
    )
    assert response.status_code == 422
    assert client.get("/v1/projects").json() == []
    engine.dispose()


def test_target_policy_rejects_unknown_potentially_sensitive_fields(
    tmp_path: Path,
) -> None:
    engine, _, _, _, _, client = _stack(tmp_path)
    response = client.post(
        "/v1/projects",
        json={
            "name": "Project",
            "target_policy": {"raw_prompt": "API_KEY=fixture-secret"},
        },
    )
    assert response.status_code == 400
    assert "fixture-secret" not in response.text
    engine.dispose()


def test_cancelled_run_is_durable_and_worker_skips_it(tmp_path: Path) -> None:
    engine, _, _, service, context, client = _stack(tmp_path)
    _, run = _create_project_and_run(client)
    cancelled = client.post(f"/v1/runs/{run['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert service.process_next(context, owner="worker") is None
    engine.dispose()


def test_service_restart_reads_persisted_run_and_artifacts(tmp_path: Path) -> None:
    engine, sessions, artifacts, service, context, client = _stack(tmp_path)
    _, run = _create_project_and_run(client)
    service.process_next(context, owner="worker")
    restarted = LabApplicationService(sessions, artifacts)
    restarted_client = ASGIClient(
        create_app(service=restarted, tenant_context=context)
    )
    assert restarted_client.get(f"/v1/runs/{run['id']}").json()["status"] == (
        "completed"
    )
    assert restarted_client.get(
        f"/v1/runs/{run['id']}/reports/json"
    ).status_code == 200
    engine.dispose()


def test_other_tenant_app_cannot_read_run_or_reports(tmp_path: Path) -> None:
    engine, _, _, service, context, client = _stack(tmp_path)
    _, run = _create_project_and_run(client)
    service.process_next(context, owner="worker")
    tenant_b = ASGIClient(
        create_app(service=service, tenant_context=TenantContext("tenant_b"))
    )
    assert tenant_b.get(f"/v1/runs/{run['id']}").status_code == 404
    assert tenant_b.get(f"/v1/runs/{run['id']}/reports/json").status_code == 404
    engine.dispose()


def test_commercial_routes_are_absent_without_explicit_service_context() -> None:
    client = ASGIClient(create_app())
    assert client.get("/v1/projects").status_code == 404
    assert client.post("/v1/runs", json={}).status_code == 404


def test_environment_server_factory_bootstraps_local_single_tenant(
    tmp_path: Path,
) -> None:
    app = create_server_app(
        {
            "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'server.db').as_posix()}",
            "LAB_ARTIFACT_ROOT": str(tmp_path / "server-artifacts"),
            "LAB_TENANT_ID": "configured_tenant",
            "LAB_TENANT_NAME": "Configured Tenant",
            "LAB_EXPOSE_DOCS": "0",
        }
    )
    client = ASGIClient(app)
    assert client.get("/v1/health/ready").json()["status"] == "ready"
    assert client.post("/v1/projects", json={"name": "Configured"}).status_code == 201
    assert client.get("/docs").status_code == 404
    app.state.engine.dispose()


def test_environment_server_factory_can_explicitly_expose_docs(tmp_path: Path) -> None:
    app = create_server_app(
        {
            "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'docs.db').as_posix()}",
            "LAB_ARTIFACT_ROOT": str(tmp_path / "docs-artifacts"),
            "LAB_EXPOSE_DOCS": "1",
        }
    )
    assert ASGIClient(app).get("/docs").status_code == 200
    app.state.engine.dispose()


def test_uvicorn_serves_real_local_health_request(tmp_path: Path) -> None:
    app = create_server_app(
        {
            "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'socket.db').as_posix()}",
            "LAB_ARTIFACT_ROOT": str(tmp_path / "socket-artifacts"),
        }
    )
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical")
    )
    server.install_signal_handlers = lambda: None
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.02)
        assert server.started
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/v1/health/ready", timeout=2
        ) as response:
            payload = json.loads(response.read())
        assert payload["status"] == "ready"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        app.state.engine.dispose()
    assert not thread.is_alive()
