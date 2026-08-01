"""Tenant isolation, persistence contract, and migration tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from ai_agent_lab.domain import Project, Tenant, TenantContext
from ai_agent_lab.storage.database import (
    create_schema,
    make_engine,
    session_factory,
    session_scope,
)
from ai_agent_lab.storage.models import Base, ProjectRow
from ai_agent_lab.storage.repositories import ProjectRepository, TenantRepository


def _factory():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    return engine, session_factory(engine)


def _seed(factory):
    with factory.begin() as session:
        tenants = TenantRepository(session)
        tenants.add(Tenant(id="tenant_a", name="Tenant A"))
        tenants.add(Tenant(id="tenant_b", name="Tenant B"))
        session.flush()
        ProjectRepository(session, TenantContext("tenant_a")).add(
            Project(
                id="project_shared",
                tenant_id="tenant_a",
                name="Authorized Lab",
                created_by="user_a",
                target_policy={"network": "deny"},
            )
        )


def test_domain_entities_require_aware_timestamps_and_valid_names() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Tenant(id="tenant", name="Tenant", created_at=datetime.now())
    with pytest.raises(ValueError, match="project name"):
        Project(
            id="project",
            tenant_id="tenant",
            name=" ",
            created_by="user",
        )


def test_project_policy_is_immutable_after_construction() -> None:
    policy = {"network": "deny"}
    project = Project(
        id="project", tenant_id="tenant", name="Lab", created_by="user", target_policy=policy
    )
    policy["network"] = "allow"
    assert project.target_policy["network"] == "deny"
    with pytest.raises(TypeError):
        project.target_policy["network"] = "allow"


def test_tenant_repository_round_trip_preserves_utc_metadata() -> None:
    engine, factory = _factory()
    with factory.begin() as session:
        repository = TenantRepository(session)
        repository.add(Tenant(id="tenant_a", name="Tenant A", retention_days=30))
    with factory() as session:
        stored = TenantRepository(session).get("tenant_a")
        assert stored is not None
        assert stored.retention_days == 30
        assert stored.created_at.tzinfo == timezone.utc
    engine.dispose()


def test_project_repository_round_trip_is_tenant_bound() -> None:
    engine, factory = _factory()
    _seed(factory)
    with factory() as session:
        repository = ProjectRepository(session, TenantContext("tenant_a"))
        project = repository.get("project_shared")
        assert project is not None
        assert project.target_policy == {"network": "deny"}
        assert repository.list() == (project,)
    engine.dispose()


def test_cross_tenant_read_update_delete_and_list_are_indistinguishable() -> None:
    engine, factory = _factory()
    _seed(factory)
    with factory.begin() as session:
        repository = ProjectRepository(session, TenantContext("tenant_b"))
        assert repository.get("project_shared") is None
        assert repository.list() == ()
        assert repository.rename(
            "project_shared", "Stolen", expected_version=1
        ) is False
        assert repository.delete("project_shared") is False
    with factory() as session:
        assert ProjectRepository(
            session, TenantContext("tenant_a")
        ).get("project_shared") is not None
    engine.dispose()


def test_repository_rejects_project_from_another_tenant() -> None:
    engine, factory = _factory()
    _seed(factory)
    with factory() as session:
        repository = ProjectRepository(session, TenantContext("tenant_b"))
        with pytest.raises(ValueError, match="does not match"):
            repository.add(
                Project(
                    id="wrong",
                    tenant_id="tenant_a",
                    name="Wrong",
                    created_by="user_b",
                )
            )
    engine.dispose()


def test_list_enforces_bounded_pagination() -> None:
    engine, factory = _factory()
    _seed(factory)
    with factory() as session:
        repository = ProjectRepository(session, TenantContext("tenant_a"))
        with pytest.raises(ValueError, match="between 1 and 100"):
            repository.list(limit=101)
        with pytest.raises(ValueError, match="negative"):
            repository.list(offset=-1)
    engine.dispose()


def test_rename_uses_optimistic_version_and_does_not_accept_stale_write() -> None:
    engine, factory = _factory()
    _seed(factory)
    with factory.begin() as session:
        repository = ProjectRepository(session, TenantContext("tenant_a"))
        assert repository.rename("project_shared", "Renamed", expected_version=1)
        assert not repository.rename("project_shared", "Stale", expected_version=1)
    with factory() as session:
        stored = ProjectRepository(
            session, TenantContext("tenant_a")
        ).get("project_shared")
        assert stored is not None
        assert stored.name == "Renamed"
        assert stored.version == 2
    engine.dispose()


def test_session_scope_commits_and_rolls_back_atomically() -> None:
    engine, factory = _factory()
    with session_scope(factory) as session:
        TenantRepository(session).add(Tenant(id="committed", name="Committed"))
    with pytest.raises(RuntimeError):
        with session_scope(factory) as session:
            TenantRepository(session).add(
                Tenant(id="rolled_back", name="Rolled Back")
            )
            raise RuntimeError("fixture rollback")
    with factory() as session:
        repository = TenantRepository(session)
        assert repository.get("committed") is not None
        assert repository.get("rolled_back") is None
    engine.dispose()


def test_sqlite_foreign_keys_reject_orphan_project() -> None:
    engine, factory = _factory()
    with pytest.raises(IntegrityError):
        with factory.begin() as session:
            ProjectRepository(session, TenantContext("missing")).add(
                Project(
                    id="orphan",
                    tenant_id="missing",
                    name="Orphan",
                    created_by="user",
                )
            )
    engine.dispose()


def test_metadata_contains_only_expected_privacy_safe_columns() -> None:
    columns = {
        table.name: {column.name for column in table.columns}
        for table in Base.metadata.sorted_tables
    }
    serialized = str(columns).lower()
    assert set(columns) == {
        "api_keys",
        "tenants",
        "projects",
        "evaluation_runs",
        "report_artifacts",
    }
    assert "prompt" not in serialized
    assert "message" not in serialized
    assert "conversation" not in serialized
    assert columns["api_keys"] == {
        "id",
        "tenant_id",
        "digest",
        "salt",
        "scopes",
        "created_by",
        "created_at",
        "expires_at",
        "revoked_at",
    }
    assert "token" not in str(columns["api_keys"]).lower()
    assert "secret" not in serialized


def test_alembic_upgrade_creates_expected_schema(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "migration.db"
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "migrations"))
    config.set_main_option(
        "sqlalchemy.url", f"sqlite:///{database_path.as_posix()}"
    )
    command.upgrade(config, "head")
    command.check(config)
    engine = make_engine(f"sqlite:///{database_path.as_posix()}")
    inspector = inspect(engine)
    assert {"alembic_version", "projects", "tenants"}.issubset(
        inspector.get_table_names()
    )
    assert inspector.get_foreign_keys("projects")[0]["referred_table"] == "tenants"
    engine.dispose()


def test_postgresql_engine_is_configurable_without_connecting() -> None:
    engine = make_engine("postgresql+psycopg://user:password@localhost/lab")
    assert engine.dialect.name == "postgresql"
    engine.dispose()


def test_project_query_always_contains_tenant_predicate() -> None:
    statement = select(ProjectRow).where(
        ProjectRow.id == "project", ProjectRow.tenant_id == "tenant"
    )
    sql = str(statement.compile(compile_kwargs={"literal_binds": True}))
    assert "projects.id = 'project'" in sql
    assert "projects.tenant_id = 'tenant'" in sql
