"""Commercial domain entities with tenant and optimistic-lock metadata."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@dataclass(frozen=True)
class TenantContext:
    """Trusted tenant scope constructed by an authentication boundary."""

    tenant_id: str

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "tenant_id")


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str
    status: str = "active"
    retention_days: int = 90
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    version: int = 1

    def __post_init__(self) -> None:
        _validate_identifier(self.id, "tenant id")
        _validate_name(self.name, "tenant name")
        if self.status not in {"active", "suspended"}:
            raise ValueError("tenant status must be active or suspended")
        if not 1 <= self.retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        _validate_version_and_time(self.version, self.created_at, self.updated_at)


@dataclass(frozen=True)
class Project:
    id: str
    tenant_id: str
    name: str
    created_by: str
    target_policy: Mapping[str, object] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    version: int = 1

    def __post_init__(self) -> None:
        _validate_identifier(self.id, "project id")
        _validate_identifier(self.tenant_id, "tenant_id")
        _validate_identifier(self.created_by, "created_by")
        _validate_name(self.name, "project name")
        _validate_version_and_time(self.version, self.created_at, self.updated_at)
        object.__setattr__(
            self, "target_policy", MappingProxyType(dict(self.target_policy))
        )


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{field_name} must be a non-empty string up to 128 chars")


def _validate_name(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(f"{field_name} must be a non-empty string up to 200 chars")


def _validate_version_and_time(
    version: int, created_at: datetime, updated_at: datetime
) -> None:
    if version < 1:
        raise ValueError("version must be positive")
    if created_at.tzinfo is None or updated_at.tzinfo is None:
        raise ValueError("entity timestamps must be timezone-aware")
    if updated_at < created_at:
        raise ValueError("updated_at cannot precede created_at")


__all__ = ["Project", "Tenant", "TenantContext", "new_id", "utc_now"]
