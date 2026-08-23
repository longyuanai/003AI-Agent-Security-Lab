"""Stable public API errors with privacy-safe serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class APIError(Exception):
    """Expected application error safe to expose to an API client."""

    status_code: int
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)


def error_envelope(
    *,
    code: str,
    message: str,
    request_id: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    """Build the frozen `/v1` error envelope."""

    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
            "details": dict(details or {}),
        }
    }


__all__ = ["APIError", "error_envelope"]
