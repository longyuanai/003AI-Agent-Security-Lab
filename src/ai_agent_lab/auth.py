"""Authentication principals, API keys, OIDC verification, and RBAC."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Protocol

import jwt
from jwt import InvalidTokenError
from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab.domain import TenantContext
from ai_agent_lab.storage.auth_repository import APIKeyRepository, StoredAPIKey


MAX_BEARER_TOKEN_LENGTH = 8192
_KEY_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    AUDITOR = "auditor"


class Permission(StrEnum):
    PROJECT_READ = "project:read"
    PROJECT_CREATE = "project:create"
    RUN_READ = "run:read"
    RUN_CREATE = "run:create"
    RUN_CANCEL = "run:cancel"
    REPORT_READ = "report:read"
    AUDIT_READ = "audit:read"
    API_KEY_MANAGE = "api_key:manage"


_ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {Permission.PROJECT_READ, Permission.RUN_READ, Permission.REPORT_READ}
    ),
    Role.OPERATOR: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.RUN_READ,
            Permission.RUN_CREATE,
            Permission.RUN_CANCEL,
            Permission.REPORT_READ,
        }
    ),
    Role.ADMIN: frozenset(Permission),
    Role.AUDITOR: frozenset({Permission.AUDIT_READ}),
}


class AuthenticationError(ValueError):
    """A deliberately detail-free authentication failure."""


class AuthorizationError(PermissionError):
    """The authenticated principal lacks a required permission."""


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[Role]
    auth_method: str

    def __post_init__(self) -> None:
        TenantContext(self.tenant_id)
        if not self.subject.strip() or len(self.subject) > 128:
            raise ValueError("principal subject must be 1-128 characters")
        if not self.roles:
            raise ValueError("principal must have at least one role")
        if not all(isinstance(role, Role) for role in self.roles):
            raise ValueError("principal roles must be recognized roles")
        if self.auth_method not in {"api_key", "oidc", "local"}:
            raise ValueError("unsupported authentication method")

    @property
    def tenant_context(self) -> TenantContext:
        return TenantContext(self.tenant_id)

    def permits(self, permission: Permission) -> bool:
        return any(permission in _ROLE_PERMISSIONS[role] for role in self.roles)


class Authenticator(Protocol):
    def authenticate(self, authorization: str | None) -> Principal: ...


@dataclass(frozen=True)
class IssuedAPIKey:
    key_id: str
    token: str
    tenant_id: str
    roles: frozenset[Role]
    expires_at: datetime


class APIKeyManager:
    """Issue and revoke high-entropy keys; plaintext tokens are never persisted."""

    def __init__(
        self, sessions: sessionmaker[Session], pepper: str, *, now: Callable[[], datetime] | None = None
    ) -> None:
        if len(pepper.encode("utf-8")) < 32:
            raise ValueError("API key pepper must contain at least 32 bytes")
        self._sessions = sessions
        self._pepper = pepper.encode("utf-8")
        self._now = now or (lambda: datetime.now(timezone.utc))

    def issue(
        self,
        *,
        tenant_id: str,
        roles: Sequence[Role],
        created_by: str,
        ttl: timedelta = timedelta(days=90),
    ) -> IssuedAPIKey:
        TenantContext(tenant_id)
        normalized_roles = frozenset(Role(role) for role in roles)
        if not normalized_roles:
            raise ValueError("API key must have at least one role")
        if not created_by.strip() or len(created_by) > 128:
            raise ValueError("created_by must be 1-128 characters")
        if not timedelta(minutes=1) <= ttl <= timedelta(days=365):
            raise ValueError("API key ttl must be between 1 minute and 365 days")
        issued_at = self._now()
        key_id = secrets.token_hex(16)
        secret = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(32)
        token = f"lab.{key_id}.{secret}"
        record = StoredAPIKey(
            key_id=key_id,
            tenant_id=tenant_id,
            digest=_digest(self._pepper, salt, secret),
            salt=salt.hex(),
            roles=normalized_roles,
            created_by=created_by,
            created_at=issued_at,
            expires_at=issued_at + ttl,
        )
        with self._sessions.begin() as session:
            APIKeyRepository(session).add(record)
        return IssuedAPIKey(
            key_id=key_id,
            token=token,
            tenant_id=tenant_id,
            roles=normalized_roles,
            expires_at=record.expires_at,
        )

    def revoke(self, key_id: str) -> bool:
        with self._sessions.begin() as session:
            return APIKeyRepository(session).revoke(key_id, now=self._now())


class APIKeyAuthenticator:
    def __init__(
        self, sessions: sessionmaker[Session], pepper: str, *, now: Callable[[], datetime] | None = None
    ) -> None:
        APIKeyManager(sessions, pepper, now=now)
        self._sessions = sessions
        self._pepper = pepper.encode("utf-8")
        self._now = now or (lambda: datetime.now(timezone.utc))

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer_token(authorization)
        parts = token.split(".")
        if (
            len(parts) != 3
            or parts[0] != "lab"
            or _KEY_ID_RE.fullmatch(parts[1]) is None
            or not 32 <= len(parts[2]) <= 64
        ):
            raise AuthenticationError("invalid credentials")
        key_id, secret = parts[1], parts[2]
        with self._sessions() as session:
            record = APIKeyRepository(session).get(key_id)
        now = self._now()
        if record is None or record.revoked_at is not None or now >= record.expires_at:
            raise AuthenticationError("invalid credentials")
        expected = _digest(self._pepper, bytes.fromhex(record.salt), secret)
        if not hmac.compare_digest(expected, record.digest):
            raise AuthenticationError("invalid credentials")
        return Principal(
            subject=f"api_key:{record.key_id}",
            tenant_id=record.tenant_id,
            roles=record.roles,
            auth_method="api_key",
        )


class OIDCAuthenticator:
    """Verify a signed OIDC ID/access token using a configured public key."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        verification_key: str | bytes,
        algorithms: Sequence[str] = ("RS256",),
        tenant_claim: str = "tenant_id",
        roles_claim: str = "roles",
        leeway_seconds: int = 30,
    ) -> None:
        allowed = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"})
        selected = tuple(algorithms)
        if not issuer or not audience or not verification_key:
            raise ValueError("OIDC issuer, audience, and verification key are required")
        if not selected or not set(selected).issubset(allowed):
            raise ValueError("OIDC algorithms must use an approved asymmetric algorithm")
        if not tenant_claim or not roles_claim:
            raise ValueError("OIDC claim names cannot be empty")
        if not 0 <= leeway_seconds <= 300:
            raise ValueError("OIDC leeway must be between 0 and 300 seconds")
        self._issuer = issuer
        self._audience = audience
        self._key = verification_key
        self._algorithms = selected
        self._tenant_claim = tenant_claim
        self._roles_claim = roles_claim
        self._leeway = leeway_seconds

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer_token(authorization)
        if token.startswith("lab."):
            raise AuthenticationError("invalid credentials")
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["sub", "iss", "aud", "iat", "exp"]},
            )
            subject = claims["sub"]
            tenant_id = claims[self._tenant_claim]
            role_values = claims[self._roles_claim]
            if not isinstance(subject, str) or not isinstance(tenant_id, str):
                raise TypeError("invalid principal claims")
            if not isinstance(role_values, list) or not all(
                isinstance(role, str) for role in role_values
            ):
                raise TypeError("invalid roles claim")
            roles = frozenset(Role(role) for role in role_values)
            return Principal(subject, tenant_id, roles, "oidc")
        except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("invalid credentials") from exc


class CompositeAuthenticator:
    def __init__(self, api_keys: APIKeyAuthenticator, oidc: OIDCAuthenticator) -> None:
        self._api_keys = api_keys
        self._oidc = oidc

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer_token(authorization)
        selected = self._api_keys if token.startswith("lab.") else self._oidc
        return selected.authenticate(f"Bearer {token}")


class StaticAuthenticator:
    """Explicit local/test authenticator; never selected as a production fallback."""

    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    def authenticate(self, authorization: str | None) -> Principal:
        del authorization
        return self._principal


def require_permission(principal: Principal, permission: Permission) -> None:
    if not principal.permits(permission):
        raise AuthorizationError("permission denied")


def _bearer_token(authorization: str | None) -> str:
    if not authorization or len(authorization) > MAX_BEARER_TOKEN_LENGTH + 7:
        raise AuthenticationError("invalid credentials")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or " " in token:
        raise AuthenticationError("invalid credentials")
    if len(token) > MAX_BEARER_TOKEN_LENGTH:
        raise AuthenticationError("invalid credentials")
    return token


def _digest(pepper: bytes, salt: bytes, secret: str) -> str:
    return hmac.new(pepper, salt + secret.encode("utf-8"), hashlib.sha256).hexdigest()


__all__ = [
    "APIKeyAuthenticator",
    "APIKeyManager",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
    "CompositeAuthenticator",
    "IssuedAPIKey",
    "OIDCAuthenticator",
    "Permission",
    "Principal",
    "Role",
    "StaticAuthenticator",
    "require_permission",
]
