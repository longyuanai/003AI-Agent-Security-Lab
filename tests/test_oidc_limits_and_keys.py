"""R1/R4 regression tests converted from the synthetic review probes."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI

from ai_agent_lab.api.server import create_server_app
from ai_agent_lab.auth import AuthenticationError, OIDCAuthenticator, Role

NOW = 2_000_000_000
Record = Callable[[str, object], None]
PrivateKey = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey
)


@pytest.fixture(scope="module")
def keys() -> tuple[rsa.RSAPrivateKey, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


@pytest.mark.parametrize("case,iat,exp,expected", [
    ("ttl_599", NOW, NOW + 599, "accepted"),
    ("ttl_600", NOW, NOW + 600, "accepted"),
    ("ttl_601_gap", NOW, NOW + 601, "rejected"),
    ("ttl_7200_gap", NOW - 3600, NOW + 3600, "rejected"),
    ("expired_31", NOW - 600, NOW - 31, "rejected"),
    ("expiry_leeway_29", NOW - 600, NOW - 29, "accepted"),
    ("expiry_leeway_30", NOW - 600, NOW - 30, "rejected"),
    ("future_iat_29", NOW + 29, NOW + 600, "accepted"),
    ("future_iat_31", NOW + 31, NOW + 600, "rejected"),
    ("missing_iat", None, NOW + 600, "rejected"),
    ("missing_exp", NOW, None, "rejected"),
    ("invalid_iat", "bad", NOW + 600, "rejected"),
    ("invalid_exp", NOW, "bad", "rejected"),
    ("numeric_string_iat_gap", str(NOW), NOW + 600, "rejected"),
    ("numeric_string_exp_gap", NOW, str(NOW + 600), "rejected"),
    ("fractional_iat_gap", NOW + 0.5, NOW + 600, "rejected"),
    ("boolean_iat_gap", True, NOW + 600, "rejected"),
    ("zero_lifetime_gap", NOW, NOW, "rejected"),
    ("negative_lifetime_gap", NOW, NOW - 5, "rejected"),
])
def test_strict_time_behavior(
    case: str, iat: object, exp: object, expected: str,
    keys: tuple[rsa.RSAPrivateKey, bytes], monkeypatch: pytest.MonkeyPatch,
    record_property: Record,
) -> None:
    clock = Mock(wraps=datetime)
    clock.now.return_value = datetime.fromtimestamp(NOW, UTC)
    private, public = keys
    claims: dict[str, object] = {
        "sub": "synthetic-user", "iss": "https://idp.example.test",
        "aud": "synthetic-review", "tenant_id": "review-tenant", "roles": ["viewer"],
    }
    if iat is not None:
        claims["iat"] = iat
    if exp is not None:
        claims["exp"] = exp
    token = jwt.encode(claims, private, algorithm="RS256")
    # Patch only after encoding: encode uses datetime as an isinstance type.
    monkeypatch.setattr(jwt.api_jwt, "datetime", clock)
    auth = OIDCAuthenticator(
        issuer="https://idp.example.test", audience="synthetic-review", verification_key=public,
    )
    try:
        auth.authenticate(f"Bearer {token}")
        actual = "accepted"
    except AuthenticationError:
        actual = "rejected"
    record_property("case", case)
    record_property("observed", actual)
    record_property("regression_for_previous_gap", case.endswith("gap"))
    assert actual == expected


def get(app: FastAPI, path: str, token: str | None = None) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://in-process.test",
        ) as client:
            return await client.get(path, headers={"Authorization": f"Bearer {token}"} if token else {})
    return asyncio.run(send())


@pytest.mark.parametrize("mode", ("oidc", "api_key+oidc"))
@pytest.mark.parametrize("key_case", ("missing_setting", "missing_file", "empty", "garbage", "ec_for_rs256"))
def test_oidc_bad_key_fails_before_side_effects(
    mode: str, key_case: str, tmp_path: Path,
    record_property: Record,
) -> None:
    env = {
        "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'review.db').as_posix()}",
        "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"), "LAB_AUTH_MODE": mode,
        "LAB_AUDIT_HASH_KEY": "synthetic-review-audit-key-32-bytes-only",
        "LAB_API_KEY_PEPPER": "synthetic-review-pepper-32-bytes-only",
        "LAB_OIDC_ISSUER": "https://idp.example.test", "LAB_OIDC_AUDIENCE": "synthetic-review",
        "LAB_OIDC_ALGORITHMS": "RS256",
    }
    public_file = tmp_path / "public.pem"
    if key_case != "missing_setting":
        env["LAB_OIDC_PUBLIC_KEY_FILE"] = str(public_file)
    if key_case == "empty":
        public_file.write_bytes(b"")
    elif key_case == "garbage":
        public_file.write_bytes(b"SYNTHETIC_NOT_A_KEY")
    elif key_case == "ec_for_rs256":
        public_file.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    with pytest.raises(ValueError):
        create_server_app(env)
    record_property("startup", "rejected")
    assert not (tmp_path / "review.db").exists()
    assert not (tmp_path / "artifacts").exists()

@pytest.mark.parametrize("mode", ("disabled", "local", "api_key"))
def test_modes_not_using_oidc_ignore_unused_public_key(
    mode: str, tmp_path: Path, record_property: Record,
) -> None:
    env = {
        "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'review.db').as_posix()}",
        "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"), "LAB_AUTH_MODE": mode,
        "LAB_ALLOW_INSECURE_LOCAL_AUTH": "1",
        "LAB_AUDIT_HASH_KEY": "synthetic-review-audit-key-32-bytes-only",
        "LAB_API_KEY_PEPPER": "synthetic-review-pepper-32-bytes-only",
        "LAB_OIDC_PUBLIC_KEY_FILE": str(tmp_path / "does-not-exist.pem"),
    }
    app = create_server_app(env)
    try:
        assert app.state.auth_mode == mode
        assert get(app, "/v1/health/ready").status_code == 200
        record_property("startup", "accepted_unused_key_compatibility")
    finally:
        app.state.engine.dispose()


def claims_now() -> dict[str, object]:
    now = int(datetime.now(UTC).timestamp())
    return {
        "sub": "synthetic-user", "iss": "https://idp.example.test", "aud": "synthetic-review",
        "tenant_id": "local", "roles": ["viewer"], "iat": now, "exp": now + 600,
    }


@pytest.mark.parametrize("field", ("iat", "exp", "nbf"))
@pytest.mark.parametrize("bad", [None, True, False, "2000000000", 2_000_000_000.5,
                                [], {}, float("nan"), float("inf"), -1])
def test_invalid_original_time_types_are_rejected(
    field: str, bad: object, keys: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    claims = claims_now()
    claims[field] = bad
    token = jwt.encode(claims, keys[0], algorithm="RS256")
    auth = OIDCAuthenticator(
        issuer="https://idp.example.test", audience="synthetic-review", verification_key=keys[1],
    )
    with pytest.raises(AuthenticationError, match="^invalid credentials$"):
        auth.authenticate(f"Bearer {token}")


@pytest.mark.parametrize("nbf,expected", [(NOW, "accepted"), (NOW + 29, "accepted"),
                                        (NOW + 31, "rejected"), (NOW + 600, "rejected")])
def test_nbf_time_and_order_boundaries(
    nbf: int, expected: str, keys: tuple[rsa.RSAPrivateKey, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = claims_now()
    claims.update(iat=NOW, exp=NOW + 600, nbf=nbf)
    token = jwt.encode(claims, keys[0], algorithm="RS256")
    clock = Mock(wraps=datetime)
    clock.now.return_value = datetime.fromtimestamp(NOW, UTC)
    monkeypatch.setattr(jwt.api_jwt, "datetime", clock)
    auth = OIDCAuthenticator(
        issuer="https://idp.example.test", audience="synthetic-review", verification_key=keys[1],
    )
    if expected == "rejected":
        with pytest.raises(AuthenticationError):
            auth.authenticate(f"Bearer {token}")
    else:
        assert auth.authenticate(f"Bearer {token}").subject == "synthetic-user"


@pytest.mark.parametrize("iat,exp", [(NOW, 10 ** 100), (10 ** 100, 10 ** 100 + 600)])
def test_huge_dates_fail_closed(iat: int, exp: int, keys: tuple[rsa.RSAPrivateKey, bytes]) -> None:
    claims = claims_now()
    claims.update(iat=iat, exp=exp)
    token = jwt.encode(claims, keys[0], algorithm="RS256")
    auth = OIDCAuthenticator(
        issuer="https://idp.example.test", audience="synthetic-review", verification_key=keys[1],
    )
    with pytest.raises(AuthenticationError):
        auth.authenticate(f"Bearer {token}")


def generate_key(algorithm: str) -> PrivateKey:
    if algorithm.startswith("RS"):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "ES384":
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == "ES512":
        return ec.generate_private_key(ec.SECP521R1())
    if algorithm == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ed448.Ed448PrivateKey.generate()


def public_pem(key: PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def server_env(tmp_path: Path, mode: str) -> dict[str, str]:
    return {
        "LAB_AUTH_MODE": mode,
        "LAB_DATABASE_URL": f"sqlite:///{(tmp_path / 'fixture.db').as_posix()}",
        "LAB_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        "LAB_OIDC_ISSUER": "https://idp.example.test", "LAB_OIDC_AUDIENCE": "synthetic-review",
        "LAB_AUDIT_HASH_KEY": "synthetic-audit-key-32-bytes-for-regression-only",
        "LAB_API_KEY_PEPPER": "synthetic-pepper-32-bytes-for-regression-only",
    }


@pytest.mark.parametrize("mode", ("oidc", "api_key+oidc"))
@pytest.mark.parametrize("key_kind", ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "Ed25519", "Ed448"))
def test_supported_keys_start_and_verify(mode: str, key_kind: str, tmp_path: Path) -> None:
    private = generate_key(key_kind)
    algorithm = "EdDSA" if key_kind.startswith("Ed") else key_kind
    path = tmp_path / "public.pem"
    path.write_bytes(public_pem(private))
    env = server_env(tmp_path, mode)
    env.update(LAB_OIDC_PUBLIC_KEY_FILE=str(path), LAB_OIDC_ALGORITHMS=algorithm)
    app = create_server_app(env)
    try:
        token = jwt.encode(claims_now(), private, algorithm=algorithm)
        assert get(app, "/v1/health/ready").status_code == 200
        assert get(app, "/v1/projects", token).status_code == 200
        assert get(app, "/v1/projects").status_code == 401
    finally:
        app.state.engine.dispose()


@pytest.mark.parametrize("key_kind,algorithms", [("RS256", "RS256,ES256"), ("ES256", "ES384"),
                                               ("ES384", "ES256"), ("Ed25519", "RS256")])
def test_mismatched_key_algorithms_rejected(key_kind: str, algorithms: str, tmp_path: Path) -> None:
    path = tmp_path / "public.pem"
    path.write_bytes(public_pem(generate_key(key_kind)))
    env = server_env(tmp_path, "oidc")
    env.update(LAB_OIDC_PUBLIC_KEY_FILE=str(path), LAB_OIDC_ALGORITHMS=algorithms)
    with pytest.raises(ValueError):
        create_server_app(env)
    assert not (tmp_path / "fixture.db").exists()
    assert not (tmp_path / "artifacts").exists()


def test_weak_rsa_rejected_and_pkcs1_public_format_supported() -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError):
        OIDCAuthenticator(issuer="issuer", audience="audience", verification_key=public_pem(weak))
    private = generate_key("RS256")
    assert isinstance(private, rsa.RSAPrivateKey)
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    OIDCAuthenticator(issuer="issuer", audience="audience", verification_key=pem,
                      algorithms=("RS256", "RS384", "RS512"))


@pytest.mark.parametrize("kind", ("private", "certificate", "permission", "symmetric", "dsa"))
def test_sensitive_or_unreadable_key_configuration_is_sanitized(
    kind: str, keys: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = keys[0]
    if kind == "private":
        material = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
    elif kind == "certificate":
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-test")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(private.public_key()).serial_number(1)
                .not_valid_before(datetime.now(UTC))
                .not_valid_after(datetime.now(UTC) + timedelta(days=1)).sign(private, hashes.SHA256()))
        material = cert.public_bytes(serialization.Encoding.PEM)
    elif kind == "symmetric":
        material = b"SYNTHETIC_SYMMETRIC_SECRET"
    elif kind == "dsa":
        material = dsa.generate_private_key(key_size=2048).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        material = b""

    def read(_: Path) -> bytes:
        if kind == "permission":
            raise PermissionError("SYNTHETIC_SENSITIVE_PATH")
        return material

    monkeypatch.setattr(Path, "read_bytes", read)
    env = server_env(tmp_path, "api_key+oidc")
    env["LAB_OIDC_PUBLIC_KEY_FILE"] = str(tmp_path / "synthetic-key")
    with pytest.raises(ValueError) as rejected:
        create_server_app(env)
    assert "SYNTHETIC_SENSITIVE_PATH" not in str(rejected.value)
    assert "BEGIN" not in str(rejected.value)
    assert rejected.value.__cause__ is None
    assert not (tmp_path / "fixture.db").exists()
    assert not (tmp_path / "artifacts").exists()


def test_combined_mode_preserves_api_key_lifetime_and_rejects_long_jwt(
    keys: tuple[rsa.RSAPrivateKey, bytes], tmp_path: Path,
) -> None:
    path = tmp_path / "public.pem"
    path.write_bytes(keys[1])
    env = server_env(tmp_path, "api_key+oidc")
    env["LAB_OIDC_PUBLIC_KEY_FILE"] = str(path)
    app = create_server_app(env)
    try:
        issued = app.state.api_key_manager.issue(tenant_id="local", roles=[Role.VIEWER],
                                               created_by="synthetic-owner", ttl=timedelta(days=30))
        assert get(app, "/v1/projects", issued.token).status_code == 200
        claims = claims_now()
        claims["exp"] = int(datetime.now(UTC).timestamp()) + 7200
        token = jwt.encode(claims, keys[0], algorithm="RS256")
        assert get(app, "/v1/projects", token).status_code == 401
        assert app.state.api_key_manager.revoke(issued.key_id)
        assert get(app, "/v1/projects", issued.token).status_code == 401
    finally:
        app.state.engine.dispose()
