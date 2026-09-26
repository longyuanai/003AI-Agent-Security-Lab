"""Privacy-safe report artifact metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ai_agent_lab.domain.entities import utc_now


@dataclass(frozen=True)
class ReportArtifact:
    id: str
    tenant_id: str
    run_id: str
    format: str
    object_key: str
    sha256: str
    size_bytes: int
    content_type: str
    expires_at: datetime
    created_at: datetime = field(default_factory=utc_now)
    deleted_at: datetime | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("artifact id", self.id),
            ("tenant_id", self.tenant_id),
            ("run_id", self.run_id),
            ("object_key", self.object_key),
        ):
            if not value or len(value) > 512:
                raise ValueError(f"{name} must be non-empty and bounded")
        if self.format not in {"json", "markdown"}:
            raise ValueError("artifact format must be json or markdown")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ValueError("artifact sha256 must be lowercase hexadecimal")
        if self.size_bytes < 0:
            raise ValueError("artifact size cannot be negative")
        for value in (self.created_at, self.expires_at, self.deleted_at):
            if value is not None and value.tzinfo is None:
                raise ValueError("artifact timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("artifact expiration must follow creation")


__all__ = ["ReportArtifact"]
