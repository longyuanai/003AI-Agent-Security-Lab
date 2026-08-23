"""Artifact integrity, path safety, TTL, and tenant isolation tests."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from ai_agent_lab.domain import EvaluationRun, Project, ReportArtifact, Tenant, TenantContext
from ai_agent_lab.storage import create_schema, make_engine, session_factory
from ai_agent_lab.storage.artifact_repository import ReportArtifactRepository
from ai_agent_lab.storage.artifact_store import (
    ArtifactIntegrityError,
    FileArtifactStore,
    build_artifact_key,
)
from ai_agent_lab.storage.repositories import ProjectRepository, TenantRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository


NOW = datetime(2026, 8, 1, 8, 0, tzinfo=timezone.utc)


def _metadata():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_schema(engine)
    factory = session_factory(engine)
    with factory.begin() as session:
        tenants = TenantRepository(session)
        tenants.add(Tenant(id="tenant_a", name="Tenant A"))
        tenants.add(Tenant(id="tenant_b", name="Tenant B"))
        session.flush()
        ProjectRepository(session, TenantContext("tenant_a")).add(Project(id="project_a", tenant_id="tenant_a", name="A", created_by="user_a"))
        ProjectRepository(session, TenantContext("tenant_b")).add(Project(id="project_b", tenant_id="tenant_b", name="B", created_by="user_b"))
        session.flush()
        EvaluationRunRepository(session, TenantContext("tenant_a")).create_idempotent(EvaluationRun(id="run_a", tenant_id="tenant_a", project_id="project_a", suite_version="v1", seed=1, idempotency_key="a", created_at=NOW, updated_at=NOW))
    return engine, factory


def _artifact(data: bytes = b"privacy-safe report") -> ReportArtifact:
    return ReportArtifact(
        id="artifact_a", tenant_id="tenant_a", run_id="run_a", format="markdown",
        object_key="tenant_a/run_a/artifact_a.md", sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data), content_type="text/markdown; charset=utf-8",
        created_at=NOW, expires_at=NOW + timedelta(days=30),
    )


def test_file_store_round_trip_and_checksum(tmp_path) -> None:
    store = FileArtifactStore(tmp_path)
    data = b"privacy-safe report"
    size, digest = store.put("tenant/run/report.md", data)
    assert size == len(data)
    assert digest == hashlib.sha256(data).hexdigest()
    assert store.read("tenant/run/report.md", expected_sha256=digest) == data


def test_file_store_rejects_traversal_absolute_and_windows_paths(tmp_path) -> None:
    store = FileArtifactStore(tmp_path)
    for key in ("../escape.md", "/absolute.md", "C:/drive.md", "tenant\\escape.md"):
        with pytest.raises(ValueError):
            store.put(key, b"data")


def test_file_store_rejects_oversize_and_overwrite(tmp_path) -> None:
    store = FileArtifactStore(tmp_path, max_bytes=4)
    with pytest.raises(ValueError, match="size limit"):
        store.put("tenant/run/large.json", b"12345")
    store.put("tenant/run/report.json", b"1234")
    with pytest.raises(FileExistsError):
        store.put("tenant/run/report.json", b"1234")


def test_file_store_detects_tampering(tmp_path) -> None:
    store = FileArtifactStore(tmp_path)
    _, digest = store.put("tenant/run/report.json", b"original")
    (tmp_path / "tenant" / "run" / "report.json").write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError, match="checksum"):
        store.read("tenant/run/report.json", expected_sha256=digest)


def test_file_store_delete_is_idempotent(tmp_path) -> None:
    store = FileArtifactStore(tmp_path)
    store.put("tenant/run/report.json", b"data")
    assert store.delete("tenant/run/report.json")
    assert not store.delete("tenant/run/report.json")


def test_file_store_rejects_symlink_component_before_writing(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "storage" / "tenant"
    link.parent.mkdir()
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available for this Windows account")
    store = FileArtifactStore(tmp_path / "storage")
    with pytest.raises(ValueError, match="symlink"):
        store.put("tenant/run/report.json", b"must-not-escape")
    assert list(outside.iterdir()) == []


def test_server_key_builder_rejects_untrusted_identifiers() -> None:
    assert build_artifact_key(tenant_id="tenant", run_id="run", artifact_id="artifact", format="json") == "tenant/run/artifact.json"
    with pytest.raises(ValueError):
        build_artifact_key(tenant_id="../tenant", run_id="run", artifact_id="artifact", format="json")
    with pytest.raises(ValueError):
        build_artifact_key(tenant_id="tenant", run_id="run", artifact_id="artifact", format="pdf")


def test_artifact_metadata_round_trip_and_soft_delete() -> None:
    engine, factory = _metadata()
    with factory.begin() as session:
        ReportArtifactRepository(session, TenantContext("tenant_a")).add(_artifact())
    with factory.begin() as session:
        repository = ReportArtifactRepository(session, TenantContext("tenant_a"))
        stored = repository.get("artifact_a")
        assert stored is not None and stored.sha256 == _artifact().sha256
        assert repository.mark_deleted("artifact_a", now=NOW + timedelta(days=1))
        assert repository.get("artifact_a") is None
    engine.dispose()


def test_artifact_metadata_cannot_cross_tenant_boundary() -> None:
    engine, factory = _metadata()
    with factory.begin() as session:
        ReportArtifactRepository(session, TenantContext("tenant_a")).add(_artifact())
    with factory.begin() as session:
        repository = ReportArtifactRepository(session, TenantContext("tenant_b"))
        assert repository.get("artifact_a") is None
        assert not repository.mark_deleted("artifact_a", now=NOW)
    engine.dispose()


def test_artifact_metadata_rejects_run_outside_tenant() -> None:
    engine, factory = _metadata()
    with factory() as session:
        with pytest.raises(ValueError, match="run was not found"):
            ReportArtifactRepository(session, TenantContext("tenant_b")).add(
                ReportArtifact(
                    id="wrong", tenant_id="tenant_b", run_id="run_a", format="json",
                    object_key="tenant_b/run_a/wrong.json", sha256="0" * 64, size_bytes=0,
                    content_type="application/json", created_at=NOW,
                    expires_at=NOW + timedelta(days=1),
                )
            )
    engine.dispose()


def test_artifact_requires_future_expiration_and_valid_hash() -> None:
    with pytest.raises(ValueError, match="expiration"):
        ReportArtifact(id="a", tenant_id="t", run_id="r", format="json", object_key="t/r/a.json", sha256="0" * 64, size_bytes=0, content_type="application/json", created_at=NOW, expires_at=NOW)
    with pytest.raises(ValueError, match="sha256"):
        ReportArtifact(id="a", tenant_id="t", run_id="r", format="json", object_key="t/r/a.json", sha256="invalid", size_bytes=0, content_type="application/json", created_at=NOW, expires_at=NOW + timedelta(days=1))
