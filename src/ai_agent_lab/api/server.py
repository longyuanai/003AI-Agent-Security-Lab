"""Environment-driven ASGI factory for single-host commercial deployment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from sqlalchemy import text

from ai_agent_lab.api import create_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.auth import (
    APIKeyAuthenticator,
    APIKeyManager,
    CompositeAuthenticator,
    OIDCAuthenticator,
    Principal,
    Role,
    StaticAuthenticator,
)
from ai_agent_lab.domain import Tenant
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
    auth_mode = env.get("LAB_AUTH_MODE", "disabled").strip().lower()
    allowed_auth_modes = {"disabled", "local", "api_key", "oidc", "api_key+oidc"}
    if auth_mode not in allowed_auth_modes:
        raise ValueError(
            "LAB_AUTH_MODE must be disabled, local, api_key, oidc, or api_key+oidc"
        )
    if (
        auth_mode == "local"
        and env.get("LAB_ALLOW_INSECURE_LOCAL_AUTH", "0").strip() != "1"
    ):
        raise ValueError("local auth requires LAB_ALLOW_INSECURE_LOCAL_AUTH=1")
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
    authenticator = None
    api_key_manager = None
    if auth_mode == "local":
        authenticator = StaticAuthenticator(
            Principal(
                subject="local_operator",
                tenant_id=tenant_id,
                roles=frozenset({Role.ADMIN}),
                auth_method="local",
            )
        )
    elif auth_mode in {"api_key", "oidc", "api_key+oidc"}:
        api_authenticator = None
        oidc_authenticator = None
        if "api_key" in auth_mode:
            pepper = env.get("LAB_API_KEY_PEPPER", "")
            api_key_manager = APIKeyManager(sessions, pepper)
            api_authenticator = APIKeyAuthenticator(sessions, pepper)
        if "oidc" in auth_mode:
            key_path = env.get("LAB_OIDC_PUBLIC_KEY_FILE", "").strip()
            if not key_path:
                raise ValueError("OIDC auth requires LAB_OIDC_PUBLIC_KEY_FILE")
            verification_key = Path(key_path).read_bytes()
            algorithms = tuple(
                part.strip()
                for part in env.get("LAB_OIDC_ALGORITHMS", "RS256").split(",")
                if part.strip()
            )
            oidc_authenticator = OIDCAuthenticator(
                issuer=env.get("LAB_OIDC_ISSUER", "").strip(),
                audience=env.get("LAB_OIDC_AUDIENCE", "").strip(),
                verification_key=verification_key,
                algorithms=algorithms,
                tenant_claim=env.get("LAB_OIDC_TENANT_CLAIM", "tenant_id").strip(),
                roles_claim=env.get("LAB_OIDC_ROLES_CLAIM", "roles").strip(),
            )
        if api_authenticator and oidc_authenticator:
            authenticator = CompositeAuthenticator(
                api_authenticator, oidc_authenticator
            )
        else:
            authenticator = api_authenticator or oidc_authenticator

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
        service=service if authenticator is not None else None,
        authenticator=authenticator,
    )
    app.state.engine = engine
    app.state.application_service = service
    app.state.api_key_manager = api_key_manager
    app.state.auth_mode = auth_mode
    return app


__all__ = ["create_server_app"]
