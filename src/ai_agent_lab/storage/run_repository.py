"""Tenant-scoped evaluation runs with durable leases and fencing tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from ai_agent_lab.domain import (
    EvaluationRun,
    LeaseClaim,
    RunStatus,
    TenantContext,
    require_transition,
)
from ai_agent_lab.storage.models import EvaluationRunRow, ProjectRow


_ACTIVE = (
    RunStatus.QUEUED.value,
    RunStatus.PREPARING.value,
    RunStatus.RUNNING.value,
    RunStatus.EVALUATING.value,
)


class EvaluationRunRepository:
    """A run/job repository permanently bound to one trusted tenant."""

    def __init__(self, session: Session, context: TenantContext) -> None:
        self._session = session
        self._tenant_id = context.tenant_id

    def create_idempotent(self, run: EvaluationRun) -> tuple[EvaluationRun, bool]:
        if run.tenant_id != self._tenant_id:
            raise ValueError("run tenant does not match repository context")
        existing = self._session.scalar(
            select(EvaluationRunRow).where(
                EvaluationRunRow.tenant_id == self._tenant_id,
                EvaluationRunRow.idempotency_key == run.idempotency_key,
            )
        )
        if existing:
            return _from_row(existing), False
        project_exists = self._session.scalar(
            select(ProjectRow.id).where(
                ProjectRow.id == run.project_id,
                ProjectRow.tenant_id == self._tenant_id,
            )
        )
        if project_exists is None:
            raise ValueError("project was not found in tenant context")
        self._session.add(_to_row(run))
        self._session.flush()
        return run, True

    def get(self, run_id: str) -> EvaluationRun | None:
        row = self._session.scalar(
            select(EvaluationRunRow).where(
                EvaluationRunRow.id == run_id,
                EvaluationRunRow.tenant_id == self._tenant_id,
            )
        )
        return _from_row(row) if row else None

    def claim_next(
        self,
        *,
        owner: str,
        now: datetime,
        lease_seconds: int = 60,
    ) -> LeaseClaim | None:
        _validate_lease(owner, now, lease_seconds)
        row = self._session.scalar(
            select(EvaluationRunRow)
            .where(
                EvaluationRunRow.tenant_id == self._tenant_id,
                EvaluationRunRow.status.in_(_ACTIVE),
                or_(
                    EvaluationRunRow.status == RunStatus.QUEUED.value,
                    EvaluationRunRow.lease_expires_at <= now,
                ),
            )
            .order_by(EvaluationRunRow.created_at, EvaluationRunRow.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if row is None:
            return None
        row.status = RunStatus.PREPARING.value
        row.lease_owner = owner
        row.lease_expires_at = now + timedelta(seconds=lease_seconds)
        row.attempt += 1
        row.fencing_token += 1
        row.version += 1
        row.updated_at = now
        self._session.flush()
        run = _from_row(row)
        return LeaseClaim(run=run, owner=owner, fencing_token=row.fencing_token)

    def heartbeat(
        self,
        claim: LeaseClaim,
        *,
        now: datetime,
        lease_seconds: int = 60,
    ) -> bool:
        _validate_lease(claim.owner, now, lease_seconds)
        result = self._session.execute(
            update(EvaluationRunRow)
            .where(
                EvaluationRunRow.id == claim.run.id,
                EvaluationRunRow.tenant_id == self._tenant_id,
                EvaluationRunRow.lease_owner == claim.owner,
                EvaluationRunRow.fencing_token == claim.fencing_token,
                EvaluationRunRow.lease_expires_at > now,
                EvaluationRunRow.status.in_(_ACTIVE),
            )
            .values(
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                updated_at=now,
                version=EvaluationRunRow.version + 1,
            )
        )
        return result.rowcount == 1

    def transition(
        self,
        claim: LeaseClaim,
        target: RunStatus,
        *,
        now: datetime,
    ) -> bool:
        current = self.get(claim.run.id)
        if current is None:
            return False
        require_transition(current.status, target)
        terminal_values = (
            {"lease_owner": None, "lease_expires_at": None}
            if target.terminal
            else {}
        )
        result = self._session.execute(
            update(EvaluationRunRow)
            .where(
                EvaluationRunRow.id == claim.run.id,
                EvaluationRunRow.tenant_id == self._tenant_id,
                EvaluationRunRow.status == current.status.value,
                EvaluationRunRow.lease_owner == claim.owner,
                EvaluationRunRow.fencing_token == claim.fencing_token,
                EvaluationRunRow.lease_expires_at > now,
            )
            .values(
                status=target.value,
                updated_at=now,
                version=EvaluationRunRow.version + 1,
                **terminal_values,
            )
        )
        return result.rowcount == 1

    def cancel(self, run_id: str, *, now: datetime) -> bool:
        current = self.get(run_id)
        if current is None:
            return False
        if current.status is RunStatus.CANCELLED:
            return True
        if current.status.terminal:
            return False
        result = self._session.execute(
            update(EvaluationRunRow)
            .where(
                EvaluationRunRow.id == run_id,
                EvaluationRunRow.tenant_id == self._tenant_id,
                EvaluationRunRow.status.in_(_ACTIVE),
            )
            .values(
                status=RunStatus.CANCELLED.value,
                lease_owner=None,
                lease_expires_at=None,
                updated_at=now,
                version=EvaluationRunRow.version + 1,
            )
        )
        return result.rowcount == 1


def _validate_lease(owner: str, now: datetime, lease_seconds: int) -> None:
    if not owner or len(owner) > 128:
        raise ValueError("lease owner must be non-empty and at most 128 chars")
    if now.tzinfo is None:
        raise ValueError("lease timestamp must be timezone-aware")
    if not 1 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 1 and 3600")


def _to_row(run: EvaluationRun) -> EvaluationRunRow:
    return EvaluationRunRow(
        id=run.id,
        tenant_id=run.tenant_id,
        project_id=run.project_id,
        suite_version=run.suite_version,
        seed=run.seed,
        idempotency_key=run.idempotency_key,
        status=run.status.value,
        attempt=run.attempt,
        fencing_token=run.fencing_token,
        lease_owner=run.lease_owner,
        lease_expires_at=run.lease_expires_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
        version=run.version,
    )


def _from_row(row: EvaluationRunRow) -> EvaluationRun:
    return EvaluationRun(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        suite_version=row.suite_version,
        seed=row.seed,
        idempotency_key=row.idempotency_key,
        status=RunStatus(row.status),
        attempt=row.attempt,
        fencing_token=row.fencing_token,
        lease_owner=row.lease_owner,
        lease_expires_at=_aware(row.lease_expires_at),
        created_at=_aware(row.created_at),
        updated_at=_aware(row.updated_at),
        version=row.version,
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo:
        return value
    return value.replace(tzinfo=timezone.utc)


__all__ = ["EvaluationRunRepository"]
