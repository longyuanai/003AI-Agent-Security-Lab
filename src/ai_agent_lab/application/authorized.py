"""Principal-aware application boundary for all user-initiated operations."""

from __future__ import annotations

from ai_agent_lab.application.service import LabApplicationService
from ai_agent_lab.auth import Permission, Principal, require_permission
from ai_agent_lab.domain import EvaluationRun, Project


class AuthorizedLabApplicationService:
    """Enforce RBAC before delegating to tenant-scoped domain operations."""

    def __init__(self, service: LabApplicationService) -> None:
        self._service = service

    def create_project(
        self,
        principal: Principal,
        *,
        name: str,
        target_policy: dict[str, object] | None = None,
    ) -> Project:
        require_permission(principal, Permission.PROJECT_CREATE)
        return self._service.create_project(
            principal.tenant_context,
            name=name,
            created_by=principal.subject,
            target_policy=target_policy,
        )

    def list_projects(self, principal: Principal) -> tuple[Project, ...]:
        require_permission(principal, Permission.PROJECT_READ)
        return self._service.list_projects(principal.tenant_context)

    def create_run(
        self,
        principal: Principal,
        *,
        project_id: str,
        suite_version: str,
        seed: int,
        idempotency_key: str,
    ) -> tuple[EvaluationRun, bool]:
        require_permission(principal, Permission.RUN_CREATE)
        return self._service.create_run(
            principal.tenant_context,
            project_id=project_id,
            suite_version=suite_version,
            seed=seed,
            idempotency_key=idempotency_key,
        )

    def get_run(self, principal: Principal, run_id: str) -> EvaluationRun | None:
        require_permission(principal, Permission.RUN_READ)
        return self._service.get_run(principal.tenant_context, run_id)

    def cancel_run(self, principal: Principal, run_id: str) -> bool:
        require_permission(principal, Permission.RUN_CANCEL)
        return self._service.cancel_run(principal.tenant_context, run_id)

    def read_report(
        self, principal: Principal, run_id: str, format_name: str
    ) -> tuple[bytes, str] | None:
        require_permission(principal, Permission.REPORT_READ)
        return self._service.read_report(
            principal.tenant_context, run_id, format_name
        )


__all__ = ["AuthorizedLabApplicationService"]
