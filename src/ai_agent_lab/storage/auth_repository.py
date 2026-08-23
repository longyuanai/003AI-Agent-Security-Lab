"""Persistence for one-way API key credentials."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ai_agent_lab.storage.models import APIKeyRow


@dataclass(frozen=True)
class StoredAPIKey:
    key_id: str
    tenant_id: str
    digest: str
    salt: str
    roles: frozenset[object]
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class APIKeyRepository:
    """System authentication repository; callers never receive plaintext keys."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, key: StoredAPIKey) -> None:
        self._session.add(
            APIKeyRow(
                id=key.key_id,
                tenant_id=key.tenant_id,
                digest=key.digest,
                salt=key.salt,
                scopes=sorted(str(role) for role in key.roles),
                created_by=key.created_by,
                created_at=key.created_at,
                expires_at=key.expires_at,
                revoked_at=key.revoked_at,
            )
        )

    def get(self, key_id: str) -> StoredAPIKey | None:
        row = self._session.scalar(select(APIKeyRow).where(APIKeyRow.id == key_id))
        return _from_row(row) if row else None

    def revoke(self, key_id: str, *, now: datetime) -> bool:
        result = self._session.execute(
            update(APIKeyRow)
            .where(APIKeyRow.id == key_id, APIKeyRow.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        return result.rowcount == 1


def _from_row(row: APIKeyRow) -> StoredAPIKey:
    # Import here to avoid a storage/auth import cycle during SQLAlchemy setup.
    from ai_agent_lab.auth import Role

    return StoredAPIKey(
        key_id=row.id,
        tenant_id=row.tenant_id,
        digest=row.digest,
        salt=row.salt,
        roles=frozenset(Role(scope) for scope in row.scopes),
        created_by=row.created_by,
        created_at=_aware(row.created_at),
        expires_at=_aware(row.expires_at),
        revoked_at=_aware(row.revoked_at) if row.revoked_at else None,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


__all__ = ["APIKeyRepository", "StoredAPIKey"]
