"""G1/G4 audit attribution: keyed identity hashes, server request IDs, run submitter."""

from __future__ import annotations

import asyncio
import io
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab.api import create_app
from ai_agent_lab.api.server import create_server_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.auth import (
    APIKeyAuthenticator,
    APIKeyManager,
    IssuedAPIKey,
    Principal,
    Role,
    StaticAuthenticator,
)
from ai_agent_lab.domain import EvaluationRun, Tenant, TenantAccessError, TenantContext
from ai_agent_lab.observability import AuditIdentityHasher, SafeJSONFormatter
from ai_agent_lab.storage import (
    FileArtifactStore,
    create_schema,
    make_engine,
    session_factory,
)
from ai_agent_lab.storage.models import ReportArtifactRow
from ai_agent_lab.storage.repositories import TenantRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository

PEPPER = "g1-synthetic-pepper-at-least-32-bytes-only"
AUDIT_KEY = "g1-synthetic-audit-hash-key-32-bytes-min"
BODY_CANARY = "SYNTHETIC_G1_BODY_CANARY"
PROJECT_CANARY = "SYNTHETIC_G1_PROJECT_NAME_CANARY"


@dataclass
class Stack:
    sessions: sessionmaker[Session]
    service: LabApplicationService
    hasher: AuditIdentityHasher
    stream: io.StringIO
    app: FastAPI
    project: str

    def events(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def issue(self, *roles: Role, tenant: str = "tenant_a") -> IssuedAPIKey:
        return APIKeyManager(self.sessions, PEPPER).issue(
            tenant_id=tenant, roles=list(roles), created_by="g1-fixture"
        )

    def suspend(self, tenant: str = "tenant_a") -> None:
        with self.sessions.begin() as session:
            repository = TenantRepository(session)
            current = repository.get(tenant)
            assert current is not None
            assert repository.set_status(tenant, "suspended", expected_version=current.version)


def _isolated_logger(name: str, stream: io.StringIO) -> logging.Logger:
    # Unregistered logger: global logging reconfiguration cannot disable it.
    logger = logging.Logger(name, level=logging.INFO)  # noqa: LOG001 - deliberate
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    return logger


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    engine = make_engine(f"sqlite:///{(tmp_path / 'g1.db').as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        for tenant_id in ("tenant_a", "tenant_b"):
            TenantRepository(session).add(Tenant(id=tenant_id, name=tenant_id))
    stream = io.StringIO()
    hasher = AuditIdentityHasher(AUDIT_KEY)
    service = LabApplicationService(
        sessions,
        FileArtifactStore(tmp_path / "artifacts"),
        logger=_isolated_logger("g1-worker", stream),
        audit_hasher=hasher,
    )
    project = service.create_project(
        TenantContext("tenant_a"), name="G1 fixture", created_by="g1-fixture"
    )
    app = create_app(
        service=service,
        authenticator=APIKeyAuthenticator(sessions, PEPPER),
        logger=_isolated_logger("g1-http", stream),
        audit_hasher=hasher,
        instance_id="api-1",
    )
    try:
        yield Stack(sessions, service, hasher, stream, app, project.id)
    finally:
        engine.dispose()


def send(app: FastAPI, method: str, path: str, **kwargs: Any) -> httpx.Response:
    async def run() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://g1.test",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def bearer(key: IssuedAPIKey) -> dict[str, str]:
    return {"Authorization": f"Bearer {key.token}"}


def create_run(stack: Stack, key: IssuedAPIKey, idempotency_key: str) -> httpx.Response:
    return send(stack.app, "POST", "/v1/runs", headers=bearer(key), json={
        "project_id": stack.project, "idempotency_key": idempotency_key,
    })


def test_hasher_is_keyed_stable_domain_separated_and_redacted() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        AuditIdentityHasher("too-short")
    hasher = AuditIdentityHasher(AUDIT_KEY)
    other = AuditIdentityHasher(AUDIT_KEY + "-other")
    assert hasher.subject("same") == hasher.subject("same")
    assert len(hasher.subject("same")) == 32
    assert hasher.subject("same") != hasher.tenant("same")
    assert hasher.subject("same") != other.subject("same")
    assert AUDIT_KEY not in repr(hasher)
    with pytest.raises(ValueError):
        hasher.subject("")


def test_identical_denials_by_two_principals_are_distinguishable(stack: Stack) -> None:
    first, second = stack.issue(Role.VIEWER), stack.issue(Role.VIEWER)
    run_id = "run_fixture_probe"
    for key in (first, second):
        response = send(stack.app, "POST", f"/v1/runs/{run_id}/cancel", headers=bearer(key))
        assert response.status_code == 403
    events = stack.events()
    assert len(events) == 2
    for event, key in zip(events, (first, second), strict=True):
        assert event["decision"] == "permission_denied"
        assert event["permission"] == "run:cancel"
        assert event["auth_method"] == "api_key"
        assert event["instance_id"] == "api-1"
        assert event["run_id"] == run_id
        assert event["subject_hash"] == stack.hasher.subject(f"api_key:{key.key_id}")
        assert event["tenant_id_hash"] == stack.hasher.tenant("tenant_a")
    assert events[0]["subject_hash"] != events[1]["subject_hash"]
    raw = stack.stream.getvalue()
    for secret in (first.token, second.token, first.key_id, "tenant_a"):
        assert secret not in raw


def test_authentication_failure_carries_no_identity(stack: Stack) -> None:
    canary = "lab." + "0" * 32 + ".SYNTHETIC_G1_TOKEN_CANARY_VALUE_0000"
    response = send(stack.app, "GET", "/v1/projects",
                    headers={"Authorization": f"Bearer {canary}"})
    assert response.status_code == 401
    (event,) = stack.events()
    assert event["decision"] == "authn_failed"
    assert not {"subject_hash", "tenant_id_hash", "auth_method"} & set(event)
    assert "SYNTHETIC_G1_TOKEN_CANARY" not in stack.stream.getvalue()


def test_client_request_id_cannot_become_the_audit_request_id(stack: Stack) -> None:
    key = stack.issue(Role.VIEWER)
    forged = "req_forged_collision_id"
    response = send(stack.app, "GET", "/v1/projects",
                    headers={**bearer(key), "X-Request-Id": forged})
    assert response.status_code == 200
    (event,) = stack.events()
    assert response.headers["x-request-id"] == event["request_id"] != forged
    assert event["client_request_id"] == forged
    assert response.headers["x-client-request-id"] == forged
    unsafe = send(stack.app, "GET", "/v1/projects",
                  headers={**bearer(key), "X-Request-Id": "bad id\twith space"})
    assert "x-client-request-id" not in unsafe.headers
    assert "client_request_id" not in stack.events()[-1]


def test_suspended_tenant_denial_is_attributed(stack: Stack) -> None:
    key = stack.issue(Role.VIEWER)
    stack.suspend()
    # API keys of a suspended tenant already fail authentication (A0 behaviour).
    assert send(stack.app, "GET", "/v1/projects", headers=bearer(key)).status_code == 401
    assert stack.events()[-1]["decision"] == "authn_failed"
    # A verified identity (e.g. OIDC claims) reaches the tenant check instead.
    principal = Principal("oidc-subject-a", "tenant_a", frozenset({Role.VIEWER}), "oidc")
    app = create_app(
        service=stack.service, authenticator=StaticAuthenticator(principal),
        logger=_isolated_logger("g1-http-static", stack.stream),
        audit_hasher=stack.hasher, instance_id="api-2",
    )
    assert send(app, "GET", "/v1/projects").status_code == 403
    event = stack.events()[-1]
    assert event["decision"] == "tenant_denied" and event["auth_method"] == "oidc"
    assert event["tenant_id_hash"] == stack.hasher.tenant("tenant_a")
    assert event["subject_hash"] == stack.hasher.subject("oidc-subject-a")
    assert event["instance_id"] == "api-2"


def test_request_bodies_never_reach_audit_log(stack: Stack) -> None:
    admin = stack.issue(Role.ADMIN)
    response = send(stack.app, "POST", "/v1/projects", headers=bearer(admin),
                    json={"name": PROJECT_CANARY, "target_policy": {}})
    assert response.status_code == 201
    denied = send(stack.app, "POST", "/v1/projects",
                  headers=bearer(stack.issue(Role.VIEWER)), json={"name": BODY_CANARY})
    assert denied.status_code == 403
    created, _ = stack.events()
    assert created["project_id"] == response.json()["id"]
    raw = stack.stream.getvalue()
    assert PROJECT_CANARY not in raw and BODY_CANARY not in raw


def test_run_records_submitter_and_idempotent_replay_keeps_it(stack: Stack) -> None:
    creator, replayer = stack.issue(Role.OPERATOR), stack.issue(Role.OPERATOR)
    created = create_run(stack, creator, "g1-run-shared-key")
    assert created.status_code == 202
    replay = create_run(stack, replayer, "g1-run-shared-key")
    assert replay.json()["id"] == created.json()["id"]
    assert "created_by" not in created.json()  # API response contract unchanged.
    with stack.sessions() as session:
        run = EvaluationRunRepository(session, TenantContext("tenant_a")).get(
            created.json()["id"]
        )
    assert run is not None and run.created_by == f"api_key:{creator.key_id}"
    first, second = stack.events()
    assert first["decision"] == "allowed" and first["run_id"] == run.id
    assert first["project_id"] == stack.project
    assert second["subject_hash"] != first["subject_hash"]


def test_worker_events_chain_request_subject_to_run_and_artifacts(stack: Stack) -> None:
    creator = stack.issue(Role.OPERATOR)
    run_id = create_run(stack, creator, "g1-worker-run").json()["id"]
    request_event = stack.events()[0]
    completed = stack.service.process_next(TenantContext("tenant_a"), owner="worker-1")
    assert completed is not None and completed.id == run_id
    worker = [event for event in stack.events() if event["event"] != "http_request"]
    assert [event["event"] for event in worker] == [
        "run_claimed", "run_stage", "artifact_committed", "artifact_committed",
        "run_completed",
    ]
    for event in worker:
        assert event["run_id"] == run_id
        assert event["worker_owner"] == "worker-1"
        assert event["fencing_token"] == 1 and event["attempt"] == 1
        assert event["submitted_by_hash"] == request_event["subject_hash"]
        assert event["tenant_id_hash"] == request_event["tenant_id_hash"]
    with stack.sessions() as session:
        rows = session.scalars(select(ReportArtifactRow)).all()
    logged = {(e["artifact_id"], e["artifact_sha256"], e["artifact_size_bytes"])
              for e in worker if e["event"] == "artifact_committed"}
    assert logged == {(row.id, row.sha256, row.size_bytes) for row in rows}


def test_worker_failure_logs_category_without_exception_text(
    stack: Stack, monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_run(stack, stack.issue(Role.OPERATOR), "g1-failing-run")
    from ai_agent_lab.application import service as service_module
    from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark

    real = evaluate_task_benchmark

    def suspend_during_evaluation(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        stack.suspend()
        return result

    monkeypatch.setattr(service_module, "evaluate_task_benchmark", suspend_during_evaluation)
    with pytest.raises(TenantAccessError):
        stack.service.process_next(TenantContext("tenant_a"), owner="worker-1")
    failed = stack.events()[-1]
    assert failed["event"] == "run_failed"
    assert failed["result"] == "tenant_denied" and failed["stage"] == "running"
    assert "tenant access denied" not in stack.stream.getvalue()  # exception text


def test_service_without_hasher_omits_hashes_and_legacy_run_has_no_submitter(
    tmp_path: Path,
) -> None:
    engine = make_engine(f"sqlite:///{(tmp_path / 'plain.db').as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        TenantRepository(session).add(Tenant(id="tenant_a", name="tenant_a"))
    stream = io.StringIO()
    service = LabApplicationService(
        sessions, FileArtifactStore(tmp_path / "artifacts"),
        logger=_isolated_logger("g1-plain-worker", stream),
    )
    context = TenantContext("tenant_a")
    project = service.create_project(context, name="Plain", created_by="g1-fixture")
    service.create_run(context, project_id=project.id, suite_version="built-in-v1",
                       seed=0, idempotency_key="legacy-caller")  # no created_by
    assert service.process_next(context, owner="worker-1") is not None
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert events and all(
        not {"tenant_id_hash", "submitted_by_hash"} & set(event) for event in events
    )
    engine.dispose()
    assert EvaluationRun(
        id="run_legacy", tenant_id="t", project_id="p", suite_version="v", seed=0,
        idempotency_key="k",
    ).created_by is None
    with pytest.raises(ValueError, match="created_by"):
        EvaluationRun(id="r", tenant_id="t", project_id="p", suite_version="v",
                      seed=0, idempotency_key="k", created_by=" ")


def _server_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    return {
        "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'server.db').as_posix()}",
        "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        "LAB_TENANT_ID": "tenant_a",
        "LAB_AUTH_MODE": "api_key",
        "LAB_API_KEY_PEPPER": PEPPER,
        **overrides,
    }


def test_authenticated_server_fails_closed_without_audit_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="LAB_AUDIT_HASH_KEY"):
        create_server_app(_server_env(tmp_path))
    with pytest.raises(ValueError, match="32 bytes"):
        create_server_app(_server_env(tmp_path, LAB_AUDIT_HASH_KEY="short"))
    with pytest.raises(ValueError, match="instance_id"):
        create_server_app(_server_env(
            tmp_path, LAB_AUDIT_HASH_KEY=AUDIT_KEY, LAB_INSTANCE_ID="bad id",
        ))
    local = create_server_app(_server_env(
        tmp_path, LAB_AUTH_MODE="local", LAB_ALLOW_INSECURE_LOCAL_AUTH="1",
    ))
    local.state.engine.dispose()


def test_migration_0005_adds_nullable_submitter_and_downgrades(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LAB_DATABASE_URL", raising=False)
    database = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    config = Config()  # No ini file: env.py must not reconfigure global logging.
    config.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[1] / "migrations")
    )
    config.set_main_option("sqlalchemy.url", database)

    def run_columns() -> dict[str, dict[str, Any]]:
        engine = make_engine(database)
        try:
            return {c["name"]: dict(c) for c in inspect(engine).get_columns("evaluation_runs")}
        finally:
            engine.dispose()

    command.upgrade(config, "0004_api_keys")
    assert "created_by" not in run_columns()
    command.upgrade(config, "head")
    command.check(config)
    assert run_columns()["created_by"]["nullable"] is True
    command.downgrade(config, "0004_api_keys")
    assert "created_by" not in run_columns()
    command.upgrade(config, "head")
    assert "created_by" in run_columns()
