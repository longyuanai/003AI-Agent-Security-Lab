"""Privacy-safe structured logging and dependency-free service metrics."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import IO


_LOG_FIELDS = (
    "event",
    "request_id",
    "method",
    "route",
    "status_code",
    "duration_ms",
    "result",
    "run_id",
    "tenant_id_hash",
    "client_request_id",
    "instance_id",
    "auth_method",
    "subject_hash",
    "decision",
    "permission",
    "project_id",
    "stage",
    "worker_owner",
    "fencing_token",
    "attempt",
    "submitted_by_hash",
    "artifact_id",
    "artifact_format",
    "artifact_sha256",
    "artifact_size_bytes",
)


class SafeJSONFormatter(logging.Formatter):
    """Allowlist log fields so headers, bodies, and exception text cannot leak."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "ai-agent-security-lab",
            "event": getattr(record, "event", "application_event"),
        }
        for field_name in _LOG_FIELDS:
            value = getattr(record, field_name, None)
            if value is not None:
                payload[field_name] = value
        return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def configure_json_logging(
    *, stream: IO[str] | None = None, level: int = logging.INFO
) -> logging.Logger:
    """Configure only the product logger; never mutate the root logger."""

    logger = logging.getLogger("ai_agent_lab")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def tenant_hash(tenant_id: str, *, salt: str) -> str:
    if not tenant_id or not salt:
        raise ValueError("tenant_id and salt are required")
    return hashlib.sha256(f"{salt}:{tenant_id}".encode()).hexdigest()[:16]


class AuditIdentityHasher:
    """Keyed, non-reversible identifiers that correlate audit events.

    Log readers without the key cannot recover or dictionary-test subjects or
    tenants; an auditor holding the key can recompute a hash to confirm one.
    """

    MIN_KEY_BYTES = 32

    def __init__(self, key: str) -> None:
        encoded = key.encode("utf-8")
        if len(encoded) < self.MIN_KEY_BYTES:
            raise ValueError("audit hash key must contain at least 32 bytes")
        self._key = encoded

    def __repr__(self) -> str:
        return "AuditIdentityHasher(<redacted>)"

    def subject(self, subject: str) -> str:
        return self._digest("subject", subject)

    def tenant(self, tenant_id: str) -> str:
        return self._digest("tenant", tenant_id)

    def _digest(self, domain: str, value: str) -> str:
        if not value:
            raise ValueError("audit identity value is required")
        message = f"{domain}\x00{value}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()[:32]


@dataclass(frozen=True)
class MetricsSnapshot:
    requests_total: dict[tuple[str, str, int], int]
    request_duration_ms_total: dict[tuple[str, str], float]
    request_duration_count: dict[tuple[str, str], int]


class MetricsRegistry:
    """Thread-safe metrics port; a Prometheus adapter can consume snapshots."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str, int], int] = defaultdict(int)
        self._duration_total: dict[tuple[str, str], float] = defaultdict(float)
        self._duration_count: dict[tuple[str, str], int] = defaultdict(int)

    def observe_request(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        if duration_ms < 0:
            raise ValueError("duration_ms cannot be negative")
        labels = (method.upper(), route)
        with self._lock:
            self._requests[(*labels, status_code)] += 1
            self._duration_total[labels] += duration_ms
            self._duration_count[labels] += 1

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(
                requests_total=dict(self._requests),
                request_duration_ms_total=dict(self._duration_total),
                request_duration_count=dict(self._duration_count),
            )


__all__ = [
    "AuditIdentityHasher",
    "MetricsRegistry",
    "MetricsSnapshot",
    "SafeJSONFormatter",
    "configure_json_logging",
    "tenant_hash",
]
