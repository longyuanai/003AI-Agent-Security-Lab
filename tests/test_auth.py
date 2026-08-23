"""Credential, OIDC, RBAC, and fail-closed API tests."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from click.testing import CliRunner
from sqlalchemy import select

from ai_agent_lab.api import create_app
from ai_agent_lab.api.server import create_server_app
from ai_agent_lab.cli import cli
from ai_agent_lab.application import AuthorizedLabApplicationService, LabApplicationService
from ai_agent_lab.auth import (
    APIKeyAuthenticator,
    APIKeyManager,
    AuthenticationError,
    OIDCAuthenticator,
    Permission,
    Principal,
    Role,
    StaticAuthenticator,
    AuthorizationError,
)
from ai_agent_lab.domain import Tenant
from ai_agent_lab.storage import FileArtifactStore, create_schema, make_engine, session_factory
from ai_agent_lab.storage.models import APIKeyRow
from ai_agent_lab.storage.repositories import TenantRepository


PEPPER = "fixture-pepper-material-that-is-at-least-32-bytes"


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


def _database(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    engine = make_engine(f"sqlite:///{(tmp_path / 'auth.db').as_posix()}")
    create_schema(engine)
    sessions = session_factory(engine)
    with sessions.begin() as session:
        tenants = TenantRepository(session)
        tenants.add(Tenant(id="tenant_a", name="Tenant A"))
        tenants.add(Tenant(id="tenant_b", name="Tenant B"))
    return engine, sessions


def _service_app(tmp_path: Path, principal: Principal):
    engine, sessions = _database(tmp_path)
    service = LabApplicationService(sessions, FileArtifactStore(tmp_path / "artifacts"))
    app = create_app(
        service=service, authenticator=StaticAuthenticator(principal)
    )
    return engine, service, Client(app)


def _principal(role: Role, *, tenant_id: str = "tenant_a") -> Principal:
    return Principal("fixture_subject", tenant_id, frozenset({role}), "local")


def _rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _oidc_token(private_key: bytes, **overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "oidc_user",
        "iss": "https://idp.example.test",
        "aud": "agent-lab",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "tenant_id": "tenant_a",
        "roles": ["operator"],
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_role_permission_matrix_is_least_privilege() -> None:
    viewer = _principal(Role.VIEWER)
    operator = _principal(Role.OPERATOR)
    admin = _principal(Role.ADMIN)
    auditor = _principal(Role.AUDITOR)
    assert viewer.permits(Permission.PROJECT_READ)
    assert not viewer.permits(Permission.RUN_CREATE)
    assert operator.permits(Permission.RUN_CREATE)
    assert not operator.permits(Permission.PROJECT_CREATE)
    assert all(admin.permits(permission) for permission in Permission)
    assert auditor.permits(Permission.AUDIT_READ)
    assert not auditor.permits(Permission.REPORT_READ)


def test_api_key_is_returned_once_and_only_digest_is_stored(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.OPERATOR], created_by="admin"
    )
    assert issued.token.startswith(f"lab.{issued.key_id}.")
    assert len(issued.token.rsplit(".", 1)[1]) >= 43
    with sessions() as session:
        row = session.scalar(select(APIKeyRow).where(APIKeyRow.id == issued.key_id))
        assert row is not None
        serialized = f"{row.digest}{row.salt}{row.scopes}{row.__dict__}"
        assert issued.token not in serialized
        assert issued.token.rsplit(".", 1)[1] not in serialized
        assert len(row.digest) == 64 and len(row.salt) == 64
    engine.dispose()


def test_api_key_authentication_maps_tenant_roles_and_subject(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_b", roles=[Role.VIEWER], created_by="admin"
    )
    principal = APIKeyAuthenticator(sessions, PEPPER).authenticate(
        f"Bearer {issued.token}"
    )
    assert principal.tenant_id == "tenant_b"
    assert principal.roles == frozenset({Role.VIEWER})
    assert principal.subject == f"api_key:{issued.key_id}"
    engine.dispose()


def test_api_key_tamper_and_wrong_pepper_are_rejected(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
    )
    tampered = issued.token[:-1] + ("A" if issued.token[-1] != "A" else "B")
    with pytest.raises(AuthenticationError, match="invalid credentials"):
        APIKeyAuthenticator(sessions, PEPPER).authenticate(f"Bearer {tampered}")
    with pytest.raises(AuthenticationError, match="invalid credentials"):
        APIKeyAuthenticator(sessions, "different-pepper-material-with-32-bytes").authenticate(
            f"Bearer {issued.token}"
        )
    engine.dispose()


def test_api_key_expiry_is_fail_closed(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)
    issued = APIKeyManager(sessions, PEPPER, now=lambda: now).issue(
        tenant_id="tenant_a",
        roles=[Role.VIEWER],
        created_by="admin",
        ttl=timedelta(minutes=1),
    )
    authenticator = APIKeyAuthenticator(
        sessions, PEPPER, now=lambda: now + timedelta(minutes=1)
    )
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(f"Bearer {issued.token}")
    engine.dispose()


def test_api_key_revocation_is_immediate_and_idempotent(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    manager = APIKeyManager(sessions, PEPPER)
    issued = manager.issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
    )
    assert manager.revoke(issued.key_id)
    assert not manager.revoke(issued.key_id)
    with pytest.raises(AuthenticationError):
        APIKeyAuthenticator(sessions, PEPPER).authenticate(f"Bearer {issued.token}")
    engine.dispose()


def test_api_key_configuration_and_bearer_format_are_validated(tmp_path: Path) -> None:
    _, sessions = _database(tmp_path)
    with pytest.raises(ValueError, match="pepper"):
        APIKeyManager(sessions, "short")
    authenticator = APIKeyAuthenticator(sessions, PEPPER)
    for header in (None, "", "Basic abc", "Bearer", "Bearer a b"):
        with pytest.raises(AuthenticationError):
            authenticator.authenticate(header)


def test_oidc_rs256_token_maps_verified_principal() -> None:
    private_key, public_key = _rsa_keys()
    authenticator = OIDCAuthenticator(
        issuer="https://idp.example.test",
        audience="agent-lab",
        verification_key=public_key,
    )
    principal = authenticator.authenticate(f"Bearer {_oidc_token(private_key)}")
    assert principal == Principal(
        "oidc_user", "tenant_a", frozenset({Role.OPERATOR}), "oidc"
    )


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://wrong.example.test"},
        {"aud": "wrong-audience"},
        {"exp": datetime(2020, 1, 1, tzinfo=timezone.utc)},
        {"roles": ["unknown-role"]},
        {"tenant_id": ""},
    ],
)
def test_oidc_rejects_invalid_identity_claims(override: dict[str, object]) -> None:
    private_key, public_key = _rsa_keys()
    authenticator = OIDCAuthenticator(
        issuer="https://idp.example.test",
        audience="agent-lab",
        verification_key=public_key,
    )
    with pytest.raises(AuthenticationError, match="invalid credentials"):
        authenticator.authenticate(f"Bearer {_oidc_token(private_key, **override)}")


def test_oidc_rejects_wrong_signature_and_non_asymmetric_configuration() -> None:
    private_key, _ = _rsa_keys()
    _, other_public_key = _rsa_keys()
    authenticator = OIDCAuthenticator(
        issuer="https://idp.example.test",
        audience="agent-lab",
        verification_key=other_public_key,
    )
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(f"Bearer {_oidc_token(private_key)}")
    with pytest.raises(ValueError, match="asymmetric"):
        OIDCAuthenticator(
            issuer="issuer", audience="audience", verification_key="secret", algorithms=["HS256"]
        )


def test_missing_authentication_returns_uniform_401_without_routes_leaking(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    service = LabApplicationService(sessions, FileArtifactStore(tmp_path / "artifacts"))
    client = Client(
        create_app(service=service, authenticator=APIKeyAuthenticator(sessions, PEPPER))
    )
    for method, path in (("GET", "/v1/projects"), ("POST", "/v1/runs")):
        response = client.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"
        assert response.headers["www-authenticate"] == "Bearer"
    engine.dispose()


def test_viewer_operator_admin_and_auditor_api_permissions(tmp_path: Path) -> None:
    engine, _, viewer = _service_app(tmp_path, _principal(Role.VIEWER))
    assert viewer.get("/v1/projects").status_code == 200
    assert viewer.post("/v1/projects", json={"name": "Denied"}).status_code == 403
    engine.dispose()

    engine, _, operator = _service_app(tmp_path / "operator", _principal(Role.OPERATOR))
    assert operator.get("/v1/projects").status_code == 200
    assert operator.post("/v1/projects", json={"name": "Denied"}).status_code == 403
    engine.dispose()

    engine, _, admin = _service_app(tmp_path / "admin", _principal(Role.ADMIN))
    assert admin.post("/v1/projects", json={"name": "Allowed"}).status_code == 201
    engine.dispose()

    engine, _, auditor = _service_app(tmp_path / "auditor", _principal(Role.AUDITOR))
    assert auditor.get("/v1/projects").status_code == 403
    engine.dispose()


def test_api_key_secret_never_enters_error_response(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    service = LabApplicationService(sessions, FileArtifactStore(tmp_path / "artifacts"))
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
    )
    response = Client(
        create_app(service=service, authenticator=APIKeyAuthenticator(sessions, PEPPER))
    ).post(
        "/v1/projects",
        headers={"Authorization": f"Bearer {issued.token}"},
        json={"name": "Denied"},
    )
    assert response.status_code == 403
    assert issued.token not in response.text
    assert issued.token.rsplit(".", 1)[1] not in response.text
    engine.dispose()


def test_commercial_routes_refuse_partial_security_configuration(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    service = LabApplicationService(sessions, FileArtifactStore(tmp_path / "artifacts"))
    with pytest.raises(ValueError, match="both service and authenticator"):
        create_app(service=service)
    with pytest.raises(ValueError, match="both service and authenticator"):
        create_app(authenticator=StaticAuthenticator(_principal(Role.ADMIN)))
    engine.dispose()


def test_application_boundary_enforces_rbac_outside_http(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    raw_service = LabApplicationService(
        sessions, FileArtifactStore(tmp_path / "artifacts")
    )
    service = AuthorizedLabApplicationService(raw_service)
    with pytest.raises(AuthorizationError, match="permission denied"):
        service.create_project(_principal(Role.OPERATOR), name="Denied")
    created = service.create_project(_principal(Role.ADMIN), name="Allowed")
    assert created.created_by == "fixture_subject"
    engine.dispose()


def test_server_defaults_to_health_only_fail_closed_mode(tmp_path: Path) -> None:
    app = create_server_app(
        {
            "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'disabled.db').as_posix()}",
            "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        }
    )
    client = Client(app)
    assert client.get("/v1/health/ready").status_code == 200
    assert client.get("/v1/projects").status_code == 404
    assert app.state.auth_mode == "disabled"
    app.state.engine.dispose()


def test_server_local_auth_requires_double_opt_in(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="LAB_ALLOW_INSECURE_LOCAL_AUTH"):
        create_server_app(
            {
                "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'local.db').as_posix()}",
                "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
                "LAB_AUTH_MODE": "local",
            }
        )


def test_server_api_key_mode_authenticates_end_to_end(tmp_path: Path) -> None:
    app = create_server_app(
        {
            "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'api-key.db').as_posix()}",
            "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "LAB_TENANT_ID": "tenant_a",
            "LAB_TENANT_NAME": "Tenant A",
            "LAB_AUTH_MODE": "api_key",
            "LAB_API_KEY_PEPPER": PEPPER,
        }
    )
    issued = app.state.api_key_manager.issue(
        tenant_id="tenant_a", roles=[Role.ADMIN], created_by="bootstrap"
    )
    client = Client(app)
    assert client.get("/v1/projects").status_code == 401
    response = client.post(
        "/v1/projects",
        headers={"Authorization": f"Bearer {issued.token}"},
        json={"name": "Authenticated"},
    )
    assert response.status_code == 201
    app.state.engine.dispose()


def test_server_rejects_unknown_auth_mode(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="LAB_AUTH_MODE"):
        create_server_app(
            {
                "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'unknown.db').as_posix()}",
                "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
                "LAB_AUTH_MODE": "anonymous",
            }
        )


def test_cli_issues_api_key_once_for_existing_tenant(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    database_url = str(engine.url)
    result = CliRunner().invoke(
        cli,
        [
            "issue-api-key",
            "--tenant",
            "tenant_a",
            "--role",
            "operator",
            "--created-by",
            "bootstrap_admin",
            "--ttl-days",
            "30",
        ],
        env={"LAB_DATABASE_URL": database_url, "LAB_API_KEY_PEPPER": PEPPER},
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["warning"].startswith("Store this token")
    assert result.output.count(payload["token"]) == 1
    assert APIKeyAuthenticator(sessions, PEPPER).authenticate(
        f"Bearer {payload['token']}"
    ).tenant_id == "tenant_a"
    engine.dispose()


def test_cli_revokes_by_public_key_id_without_plaintext(tmp_path: Path) -> None:
    engine, sessions = _database(tmp_path)
    issued = APIKeyManager(sessions, PEPPER).issue(
        tenant_id="tenant_a", roles=[Role.VIEWER], created_by="admin"
    )
    result = CliRunner().invoke(
        cli,
        ["revoke-api-key", "--key-id", issued.key_id],
        env={"LAB_DATABASE_URL": str(engine.url), "LAB_API_KEY_PEPPER": PEPPER},
    )
    assert result.exit_code == 0, result.output
    assert issued.token not in result.output
    with pytest.raises(AuthenticationError):
        APIKeyAuthenticator(sessions, PEPPER).authenticate(f"Bearer {issued.token}")
    engine.dispose()
