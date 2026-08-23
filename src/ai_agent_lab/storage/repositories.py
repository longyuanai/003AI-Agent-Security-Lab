"""Tenant-scoped SQLAlchemy repositories."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from ai_agent_lab.domain import Project, Tenant, TenantContext
from ai_agent_lab.storage.models import ProjectRow, TenantRow


class TenantRepository:
    """System-level tenant repository; callers require admin authorization."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, tenant: Tenant) -> None:
        self._session.add(
            TenantRow(
                id=tenant.id,
                name=tenant.name,
                status=tenant.status,
                retention_days=tenant.retention_days,
                created_at=tenant.created_at,
                updated_at=tenant.updated_at,
                version=tenant.version,
            )
        )

    def get(self, tenant_id: str) -> Tenant | None:
        row = self._session.get(TenantRow, tenant_id)
        return _tenant_from_row(row) if row else None


class ProjectRepository:
    """A repository permanently bound to one trusted tenant context."""

    def __init__(self, session: Session, context: TenantContext) -> None:
        self._session = session
        self._tenant_id = context.tenant_id

    def add(self, project: Project) -> None:
        if project.tenant_id != self._tenant_id:
            raise ValueError("project tenant does not match repository context")
        self._session.add(
            ProjectRow(
                id=project.id,
                tenant_id=project.tenant_id,
                name=project.name,
                created_by=project.created_by,
                target_policy=dict(project.target_policy),
                created_at=project.created_at,
                updated_at=project.updated_at,
                version=project.version,
            )
        )

    def get(self, project_id: str) -> Project | None:
        row = self._session.scalar(
            select(ProjectRow).where(
                ProjectRow.id == project_id,
                ProjectRow.tenant_id == self._tenant_id,
            )
        )
        return _project_from_row(row) if row else None

    def list(self, *, limit: int = 100, offset: int = 0) -> tuple[Project, ...]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        rows = self._session.scalars(
            select(ProjectRow)
            .where(ProjectRow.tenant_id == self._tenant_id)
            .order_by(ProjectRow.created_at, ProjectRow.id)
            .limit(limit)
            .offset(offset)
        )
        return tuple(_project_from_row(row) for row in rows)

    def rename(
        self, project_id: str, name: str, *, expected_version: int
    ) -> bool:
        # Constructing the replacement validates the public name constraints.
        existing = self.get(project_id)
        if existing is None:
            return False
        validated = Project(
            id=existing.id,
            tenant_id=existing.tenant_id,
            name=name,
            created_by=existing.created_by,
            target_policy=existing.target_policy,
            created_at=existing.created_at,
            updated_at=datetime.now(timezone.utc),
            version=existing.version,
        )
        result = self._session.execute(
            update(ProjectRow)
            .where(
                ProjectRow.id == project_id,
                ProjectRow.tenant_id == self._tenant_id,
                ProjectRow.version == expected_version,
            )
            .values(
                name=validated.name,
                updated_at=validated.updated_at,
                version=ProjectRow.version + 1,
            )
        )
        return result.rowcount == 1

    def delete(self, project_id: str) -> bool:
        result = self._session.execute(
            delete(ProjectRow).where(
                ProjectRow.id == project_id,
                ProjectRow.tenant_id == self._tenant_id,
            )
        )
        return result.rowcount == 1


def _tenant_from_row(row: TenantRow) -> Tenant:
    return Tenant(
        id=row.id,
        name=row.name,
        status=row.status,
        retention_days=row.retention_days,
        created_at=_aware(row.created_at),
        updated_at=_aware(row.updated_at),
        version=row.version,
    )


def _project_from_row(row: ProjectRow) -> Project:
    return Project(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        created_by=row.created_by,
        target_policy=dict(row.target_policy),
        created_at=_aware(row.created_at),
        updated_at=_aware(row.updated_at),
        version=row.version,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


__all__ = ["ProjectRepository", "TenantRepository"]
