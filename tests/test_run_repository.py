"""Durable run state machine, idempotency, lease, and fencing tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ai_agent_lab.domain import (
    EvaluationRun,
    Project,
    RunStatus,
    Tenant,
    TenantContext,
    require_transition,
)
from ai_agent_lab.storage import create_schema, make_engine, session_factory
from ai_agent_lab.storage.repositories import ProjectRepository, TenantRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository


NOW = datetime(2026, 8, 1, 8, 0, tzinfo=timezone.utc)


def _setup():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    factory = session_factory(engine)
    with factory.begin() as session:
        tenant_repo = TenantRepository(session)
        tenant_repo.add(Tenant(id="tenant_a", name="Tenant A"))
        tenant_repo.add(Tenant(id="tenant_b", name="Tenant B"))
        session.flush()
        ProjectRepository(session, TenantContext("tenant_a")).add(
            Project(
                id="project_a",
                tenant_id="tenant_a",
                name="Project A",
                created_by="user_a",
            )
        )
        ProjectRepository(session, TenantContext("tenant_b")).add(
            Project(
                id="project_b",
                tenant_id="tenant_b",
                name="Project B",
                created_by="user_b",
            )
        )
    return engine, factory


def _run(
    *,
    run_id: str = "run_a",
    tenant: str = "tenant_a",
    project: str = "project_a",
    key: str = "idem_a",
) -> EvaluationRun:
    return EvaluationRun(
        id=run_id,
        tenant_id=tenant,
        project_id=project,
        suite_version="suite-v1",
        seed=2026,
        idempotency_key=key,
        created_at=NOW,
        updated_at=NOW,
    )


def _create(factory, run: EvaluationRun | None = None) -> EvaluationRun:
    item = run or _run()
    with factory.begin() as session:
        stored, created = EvaluationRunRepository(
            session, TenantContext(item.tenant_id)
        ).create_idempotent(item)
        assert created
        return stored


def test_state_machine_accepts_only_forward_or_terminal_transitions() -> None:
    require_transition(RunStatus.QUEUED, RunStatus.PREPARING)
    require_transition(RunStatus.RUNNING, RunStatus.FAILED)
    with pytest.raises(ValueError, match="invalid run transition"):
        require_transition(RunStatus.COMPLETED, RunStatus.RUNNING)
    with pytest.raises(ValueError, match="invalid run transition"):
        require_transition(RunStatus.RUNNING, RunStatus.PREPARING)


def test_create_is_idempotent_within_tenant() -> None:
    engine, factory = _setup()
    first = _run()
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        stored, created = repository.create_idempotent(first)
        repeated, created_again = repository.create_idempotent(
            _run(run_id="different_run")
        )
        assert created
        assert not created_again
        assert repeated.id == stored.id
    engine.dispose()


def test_same_idempotency_key_isolated_between_tenants() -> None:
    engine, factory = _setup()
    _create(factory, _run(key="shared"))
    second = _run(
        run_id="run_b", tenant="tenant_b", project="project_b", key="shared"
    )
    _create(factory, second)
    with factory() as session:
        assert EvaluationRunRepository(
            session, TenantContext("tenant_b")
        ).get("run_b") is not None
    engine.dispose()


def test_run_creation_requires_project_in_same_tenant() -> None:
    engine, factory = _setup()
    with factory() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        with pytest.raises(ValueError, match="project was not found"):
            repository.create_idempotent(_run(project="project_b"))
    engine.dispose()


def test_cross_tenant_get_and_cancel_return_not_found_semantics() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_b"))
        assert repository.get("run_a") is None
        assert not repository.cancel("run_a", now=NOW)
    engine.dispose()


def test_claim_oldest_run_sets_attempt_lease_and_fencing_token() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        claim = EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).claim_next(owner="worker_a", now=NOW, lease_seconds=30)
        assert claim is not None
        assert claim.run.status is RunStatus.PREPARING
        assert claim.run.attempt == 1
        assert claim.fencing_token == 1
        assert claim.run.lease_expires_at == NOW + timedelta(seconds=30)
    engine.dispose()


def test_active_lease_cannot_be_claimed_twice() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        assert repository.claim_next(owner="worker_a", now=NOW) is not None
        assert repository.claim_next(owner="worker_b", now=NOW) is None
    engine.dispose()


def test_expired_lease_is_reclaimed_with_new_fencing_token() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        first = EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).claim_next(owner="worker_a", now=NOW, lease_seconds=10)
        assert first is not None
    with factory.begin() as session:
        second = EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).claim_next(owner="worker_b", now=NOW + timedelta(seconds=11))
        assert second is not None
        assert second.fencing_token == first.fencing_token + 1
        assert second.run.attempt == 2
    engine.dispose()


def test_stale_worker_cannot_heartbeat_or_transition_after_reclaim() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        stale = repository.claim_next(owner="worker_a", now=NOW, lease_seconds=10)
        assert stale is not None
    with factory.begin() as session:
        current = EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).claim_next(owner="worker_b", now=NOW + timedelta(seconds=11))
        assert current is not None
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        assert not repository.heartbeat(stale, now=NOW + timedelta(seconds=12))
        assert not repository.transition(
            stale, RunStatus.RUNNING, now=NOW + timedelta(seconds=12)
        )
    engine.dispose()


def test_expired_worker_cannot_extend_or_transition_before_reclaim() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        claim = repository.claim_next(owner="worker_a", now=NOW, lease_seconds=10)
        assert claim is not None
    expired_at = NOW + timedelta(seconds=11)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        assert not repository.heartbeat(claim, now=expired_at)
        assert not repository.transition(claim, RunStatus.RUNNING, now=expired_at)
    engine.dispose()


def test_valid_claim_can_heartbeat_and_complete_forward_chain() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        claim = repository.claim_next(owner="worker", now=NOW)
        assert claim is not None
        assert repository.heartbeat(claim, now=NOW + timedelta(seconds=5))
        assert repository.transition(
            claim, RunStatus.RUNNING, now=NOW + timedelta(seconds=6)
        )
        assert repository.transition(
            claim, RunStatus.EVALUATING, now=NOW + timedelta(seconds=7)
        )
        assert repository.transition(
            claim, RunStatus.COMPLETED, now=NOW + timedelta(seconds=8)
        )
    with factory() as session:
        completed = EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).get("run_a")
        assert completed is not None
        assert completed.status is RunStatus.COMPLETED
        assert completed.lease_owner is None
    engine.dispose()


def test_invalid_transition_does_not_modify_run() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        claim = repository.claim_next(owner="worker", now=NOW)
        assert claim is not None
        with pytest.raises(ValueError, match="invalid run transition"):
            repository.transition(claim, RunStatus.COMPLETED, now=NOW)
    with factory() as session:
        assert EvaluationRunRepository(
            session, TenantContext("tenant_a")
        ).get("run_a").status is RunStatus.PREPARING
    engine.dispose()


def test_cancel_is_idempotent_and_terminal_runs_are_not_claimed() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory.begin() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        assert repository.cancel("run_a", now=NOW)
        assert repository.cancel("run_a", now=NOW)
        assert repository.claim_next(owner="worker", now=NOW) is None
    engine.dispose()


def test_lease_validation_rejects_naive_time_and_unbounded_duration() -> None:
    engine, factory = _setup()
    _create(factory)
    with factory() as session:
        repository = EvaluationRunRepository(session, TenantContext("tenant_a"))
        with pytest.raises(ValueError, match="timezone-aware"):
            repository.claim_next(owner="worker", now=datetime.now())
        with pytest.raises(ValueError, match="between 1 and 3600"):
            repository.claim_next(owner="worker", now=NOW, lease_seconds=3601)
    engine.dispose()
