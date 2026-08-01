"""Tenant-scoped report artifact metadata repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ai_agent_lab.domain import ReportArtifact, TenantContext
from ai_agent_lab.storage.models import EvaluationRunRow, ReportArtifactRow


class ReportArtifactRepository:
    def __init__(self, session: Session, context: TenantContext) -> None:
        self._session = session
        self._tenant_id = context.tenant_id

    def add(self, artifact: ReportArtifact) -> None:
        if artifact.tenant_id != self._tenant_id:
            raise ValueError("artifact tenant does not match repository context")
        run_exists = self._session.scalar(
            select(EvaluationRunRow.id).where(
                EvaluationRunRow.id == artifact.run_id,
                EvaluationRunRow.tenant_id == self._tenant_id,
            )
        )
        if run_exists is None:
            raise ValueError("run was not found in tenant context")
        self._session.add(
            ReportArtifactRow(
                id=artifact.id,
                tenant_id=artifact.tenant_id,
                run_id=artifact.run_id,
                format=artifact.format,
                object_key=artifact.object_key,
                sha256=artifact.sha256,
                size_bytes=artifact.size_bytes,
                content_type=artifact.content_type,
                expires_at=artifact.expires_at,
                created_at=artifact.created_at,
                deleted_at=artifact.deleted_at,
            )
        )

    def get(self, artifact_id: str) -> ReportArtifact | None:
        row = self._session.scalar(
            select(ReportArtifactRow).where(
                ReportArtifactRow.id == artifact_id,
                ReportArtifactRow.tenant_id == self._tenant_id,
                ReportArtifactRow.deleted_at.is_(None),
            )
        )
        return _from_row(row) if row else None

    def get_for_run(
        self, run_id: str, format_name: str
    ) -> ReportArtifact | None:
        row = self._session.scalar(
            select(ReportArtifactRow).where(
                ReportArtifactRow.run_id == run_id,
                ReportArtifactRow.tenant_id == self._tenant_id,
                ReportArtifactRow.format == format_name,
                ReportArtifactRow.deleted_at.is_(None),
            )
        )
        return _from_row(row) if row else None

    def mark_deleted(self, artifact_id: str, *, now: datetime) -> bool:
        result = self._session.execute(
            update(ReportArtifactRow)
            .where(
                ReportArtifactRow.id == artifact_id,
                ReportArtifactRow.tenant_id == self._tenant_id,
                ReportArtifactRow.deleted_at.is_(None),
            )
            .values(deleted_at=now)
        )
        return result.rowcount == 1


def _from_row(row: ReportArtifactRow) -> ReportArtifact:
    return ReportArtifact(
        id=row.id,
        tenant_id=row.tenant_id,
        run_id=row.run_id,
        format=row.format,
        object_key=row.object_key,
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        content_type=row.content_type,
        expires_at=_aware(row.expires_at),
        created_at=_aware(row.created_at),
        deleted_at=_aware(row.deleted_at),
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo:
        return value
    return value.replace(tzinfo=timezone.utc)


__all__ = ["ReportArtifactRepository"]
