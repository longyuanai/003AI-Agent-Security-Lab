"""Offline material safeguards and deployment limitations, not live acceptance."""

from __future__ import annotations

import asyncio
import io
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI

from ai_agent_lab.api import create_app
from ai_agent_lab.api.server import create_server_app
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.auth import OIDCAuthenticator, Principal, Role, StaticAuthenticator
from ai_agent_lab.observability import SafeJSONFormatter
from scripts import deployment_authorization_materials as materials


def test_prepare_never_implies_real_acceptance_and_preserves_existing_files(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    args = ["prepare", "--output-dir", str(out), "--campaign", "authval-20260928"]
    assert materials.main(args) == 0
    before = (out / "evidence-template.json").read_bytes()
    evidence = json.loads(before)
    assert evidence["deployment_status"] == "not_verified"
    assert len(evidence["cases"]) == len(set(materials.CASE_IDS))
    assert all(case["status"] == "not_run" for case in evidence["cases"])
    assert materials.main(args) == 2
    assert (out / "evidence-template.json").read_bytes() == before


def test_unresolved_and_fully_described_decisions_both_exit_unverified(tmp_path: Path) -> None:
    materials.prepare(tmp_path / "bundle", "authval-20260928")
    config = tmp_path / "bundle/config.json"
    assert materials.main(["check", "--config", str(config)]) == 4
    value = materials.read_json(config)
    value["decisions"] = dict.fromkeys(value["decisions"], "DECISION RECORDED, NOT EXECUTED")
    config.write_text(json.dumps(value), encoding="utf-8")
    assert materials.check_config(config)["decision_metadata_complete"] is True
    assert materials.main(["check", "--config", str(config)]) == 4


@pytest.mark.parametrize("campaign", ("prod", "authval-../escape", "authval-a", "authval-ABCDEFGH"))
def test_campaign_scope_is_restricted(tmp_path: Path, campaign: str) -> None:
    out = tmp_path / "never-created"
    assert materials.main(["prepare", "--output-dir", str(out), "--campaign", campaign]) == 2
    assert not out.exists()


def test_cleanup_only_lists_exact_synthetic_manifest_and_has_no_apply(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    materials.prepare(out, "authval-20260928")
    plan = materials.cleanup_plan(out)
    assert plan["dry_run"] is True and plan["deleted"] == 0
    with pytest.raises(SystemExit) as rejected:
        materials.main(["cleanup-plan", "--bundle", str(out), "--apply"])
    assert rejected.value.code == 2
    path = out / "synthetic-resources.json"
    value = materials.read_json(path)
    value["tenants"].append("other-tenant")
    path.write_text(json.dumps(value), encoding="utf-8")
    assert materials.main(["cleanup-plan", "--bundle", str(out)]) == 2
    assert path.exists()


def test_config_rejects_production_and_does_not_echo_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "bundle"
    materials.prepare(out, "authval-20260928")
    path = out / "config.json"
    value = materials.read_json(path)
    value["environment_kind"] = "production"
    value["unexpected_password"] = "SYNTHETIC_DO_NOT_ECHO"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert materials.main(["check", "--config", str(path)]) == 2
    assert "SYNTHETIC_DO_NOT_ECHO" not in capsys.readouterr().out


def test_every_evidence_case_is_documented() -> None:
    plan = (materials.ROOT / "docs/deployment-authorization-validation-plan.md").read_text(encoding="utf-8")
    assert all(f"| {case} |" in plan for case in materials.CASE_IDS)


def keypair() -> tuple[bytes, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def token(private: bytes, role: str = "operator") -> str:
    now = datetime.now(UTC)
    return jwt.encode({
        "sub": "authval-user", "iss": "https://idp.example.test", "aud": "authval-test",
        "iat": now, "exp": now + timedelta(minutes=5),
        "tenant_id": "authval-20260928-a", "roles": [role],
    }, private, algorithm="RS256")


def request(app: FastAPI, bearer: str, *, method: str = "GET") -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://in-process.test",
        ) as client:
            return await client.request(method, "/v1/projects", headers={
                "Authorization": f"Bearer {bearer}", "X-Request-ID": "authval-request-01",
            }, json={"name": "SYNTHETIC_BODY_CANARY"} if method == "POST" else None)
    return asyncio.run(send())


def test_static_public_key_rotation_requires_new_app_instance(tmp_path: Path) -> None:
    old_private, old_public = keypair()
    new_private, new_public = keypair()
    public_file = tmp_path / "public.pem"
    public_file.write_bytes(old_public)  # Public keys only; no private key is persisted.
    env = {
        "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'fixture.db').as_posix()}",
        "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        "LAB_AUTH_MODE": "oidc", "LAB_TENANT_ID": "authval-20260928-a",
        "LAB_OIDC_PUBLIC_KEY_FILE": str(public_file),
        "LAB_OIDC_ISSUER": "https://idp.example.test", "LAB_OIDC_AUDIENCE": "authval-test",
        "LAB_AUDIT_HASH_KEY": "synthetic-audit-hash-key-for-tests-only-32b",
    }
    old_app = create_server_app(env)
    try:
        public_file.write_bytes(new_public)
        assert request(old_app, token(old_private)).status_code == 200
        assert request(old_app, token(new_private)).status_code == 401
        new_app = create_server_app(env)
        try:
            assert request(new_app, token(new_private)).status_code == 200
            assert request(new_app, token(old_private)).status_code == 401
        finally:
            new_app.state.engine.dispose()
    finally:
        old_app.state.engine.dispose()


def test_new_role_token_does_not_invalidate_existing_signed_token() -> None:
    private, public = keypair()
    authenticator = OIDCAuthenticator(
        issuer="https://idp.example.test", audience="authval-test", verification_key=public,
    )
    old_admin = token(private, "admin")
    assert authenticator.authenticate(f"Bearer {token(private, 'viewer')}").roles == frozenset({Role.VIEWER})
    assert authenticator.authenticate(f"Bearer {old_admin}").roles == frozenset({Role.ADMIN})


def test_current_http_log_has_request_correlation_but_no_actor_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    logger = logging.getLogger("authval-local-evidence")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "level", logging.INFO)
    monkeypatch.setattr(logger, "propagate", False)
    principal = Principal("authval-user", "authval-20260928-a", frozenset({Role.VIEWER}), "local")
    app = create_app(service=Mock(spec=LabApplicationService),
                     authenticator=StaticAuthenticator(principal), logger=logger)
    response = request(app, "SYNTHETIC_TOKEN_CANARY", method="POST")
    assert response.status_code == 403
    event = json.loads(stream.getvalue())
    assert event["request_id"] == response.headers["X-Request-ID"]
    assert event["route"] == "/v1/projects" and event["status_code"] == 403
    assert "tenant_id_hash" not in event and "subject" not in event
    assert "SYNTHETIC_TOKEN_CANARY" not in stream.getvalue()
    assert "SYNTHETIC_BODY_CANARY" not in stream.getvalue()
