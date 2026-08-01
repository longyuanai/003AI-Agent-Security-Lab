"""Environment-driven ASGI factory for single-host commercial deployment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from sqlalchemy import text

from ai_agent_lab.api import create_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.domain import Tenant, TenantContext
from ai_agent_lab.observability import configure_json_logging
from ai_agent_lab.storage import FileArtifactStore, create_schema, make_engine, session_factory
from ai_agent_lab.storage.repositories import TenantRepository


def create_server_app(environ: Mapping[str, str] | None = None):
    """Build the service. Production PostgreSQL schema is never auto-created."""

    env = os.environ if environ is None else environ
    database_url = env.get("LAB_DATABASE_URL", "sqlite:///./data/lab.db").strip()
    artifact_root = Path(
        env.get("LAB_ARTIFACT_ROOT", "./data/artifacts").strip()
    )
    tenant_id = env.get("LAB_TENANT_ID", "local").strip()
    tenant_name = env.get("LAB_TENANT_NAME", "Local Tenant").strip()
    retention_days = int(env.get("LAB_ARTIFACT_RETENTION_DAYS", "30"))
    expose_docs = env.get("LAB_EXPOSE_DOCS", "0").strip() == "1"
    engine = make_engine(database_url)
    sessions = session_factory(engine)
    if engine.dialect.name == "sqlite":
        create_schema(engine)
        with sessions.begin() as session:
            repository = TenantRepository(session)
            if repository.get(tenant_id) is None:
                repository.add(Tenant(id=tenant_id, name=tenant_name))
    artifacts = FileArtifactStore(artifact_root)
    service = LabApplicationService(
        sessions, artifacts, artifact_retention_days=retention_days
    )

    def ready() -> bool:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return artifact_root.exists() and artifact_root.is_dir()
        except Exception:  # noqa: BLE001 - health response hides dependency details
            return False

    logger = configure_json_logging()
    app = create_app(
        readiness_check=ready,
        expose_docs=expose_docs,
        logger=logger,
        service=service,
        tenant_context=TenantContext(tenant_id),
    )
    app.state.engine = engine
    app.state.application_service = service
    return app


__all__ = ["create_server_app"]
