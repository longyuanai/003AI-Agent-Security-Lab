"""Evaluation run state machine and lease-safe domain records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ai_agent_lab.domain.entities import utc_now


class RunStatus(str, Enum):
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


_TRANSITIONS = {
    RunStatus.QUEUED: {RunStatus.PREPARING, RunStatus.FAILED, RunStatus.CANCELLED},
    RunStatus.PREPARING: {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.CANCELLED},
    RunStatus.RUNNING: {RunStatus.EVALUATING, RunStatus.FAILED, RunStatus.CANCELLED},
    RunStatus.EVALUATING: {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED},
    RunStatus.COMPLETED: set(),
    RunStatus.FAILED: set(),
    RunStatus.CANCELLED: set(),
}


def require_transition(current: RunStatus, target: RunStatus) -> None:
    if target not in _TRANSITIONS[current]:
        raise ValueError(f"invalid run transition: {current.value} -> {target.value}")


@dataclass(frozen=True)
class EvaluationRun:
    id: str
    tenant_id: str
    project_id: str
    suite_version: str
    seed: int
    idempotency_key: str
    status: RunStatus = RunStatus.QUEUED
    attempt: int = 0
    fencing_token: int = 0
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    version: int = 1

    def __post_init__(self) -> None:
        for name, value in (
            ("run id", self.id),
            ("tenant_id", self.tenant_id),
            ("project_id", self.project_id),
            ("suite_version", self.suite_version),
            ("idempotency_key", self.idempotency_key),
        ):
            if not value or len(value) > 128:
                raise ValueError(f"{name} must be non-empty and at most 128 chars")
        if self.seed < 0 or self.attempt < 0 or self.fencing_token < 0:
            raise ValueError("seed, attempt, and fencing_token must be non-negative")
        if self.version < 1:
            raise ValueError("version must be positive")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("run timestamps must be timezone-aware")
        if self.lease_expires_at and self.lease_expires_at.tzinfo is None:
            raise ValueError("lease expiration must be timezone-aware")
        if bool(self.lease_owner) != bool(self.lease_expires_at):
            raise ValueError("lease owner and expiration must be set together")
        if self.status.terminal and self.lease_owner:
            raise ValueError("terminal run cannot retain a lease")


@dataclass(frozen=True)
class LeaseClaim:
    run: EvaluationRun
    owner: str
    fencing_token: int


__all__ = ["EvaluationRun", "LeaseClaim", "RunStatus", "require_transition"]
