"""Transactional project/run use cases and offline benchmark worker."""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab import __version__
from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark
from ai_agent_lab.domain import (
    EvaluationRun,
    LeaseClaim,
    Project,
    ReportArtifact,
    RunStatus,
    TenantAccessError,
    TenantContext,
)
from ai_agent_lab.domain.entities import new_id
from ai_agent_lab.judge import StubLabJudge
from ai_agent_lab.observability import AuditIdentityHasher
from ai_agent_lab.report import (
    build_benchmark_evidence,
    render_benchmark_markdown,
)
from ai_agent_lab.storage.artifact_repository import ReportArtifactRepository
from ai_agent_lab.storage.artifact_store import ArtifactStore, build_artifact_key
from ai_agent_lab.storage.repositories import ProjectRepository, TenantRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository


class LabApplicationService:
    """Application boundary; HTTP and CLI adapters contain no business rules."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        artifacts: ArtifactStore,
        *,
        artifact_retention_days: int = 30,
        logger: logging.Logger | None = None,
        audit_hasher: AuditIdentityHasher | None = None,
    ) -> None:
        if not 1 <= artifact_retention_days <= 3650:
            raise ValueError("artifact retention must be between 1 and 3650 days")
        self._sessions = sessions
        self._artifacts = artifacts
        self._retention_days = artifact_retention_days
        self._logger = logger or logging.getLogger("ai_agent_lab.worker")
        self._audit_hasher = audit_hasher

    def create_project(
        self,
        context: TenantContext,
        *,
        name: str,
        created_by: str,
        target_policy: dict[str, object] | None = None,
    ) -> Project:
        policy = target_policy or {}
        if not set(policy).issubset(
            {"network", "allowed_targets", "max_iterations"}
        ):
            raise ValueError("target policy contains an unsupported field")
        project = Project(
            id=new_id("prj"),
            tenant_id=context.tenant_id,
            name=name,
            created_by=created_by,
            target_policy=policy,
        )
        with self._sessions.begin() as session:
            _require_active_tenant(session, context)
            ProjectRepository(session, context).add(project)
        return project

    def list_projects(self, context: TenantContext) -> tuple[Project, ...]:
        with self._sessions() as session:
            _require_active_tenant(session, context)
            return ProjectRepository(session, context).list()

    def create_run(
        self,
        context: TenantContext,
        *,
        project_id: str,
        suite_version: str,
        seed: int,
        idempotency_key: str,
        created_by: str | None = None,
    ) -> tuple[EvaluationRun, bool]:
        run = EvaluationRun(
            id=new_id("run"),
            tenant_id=context.tenant_id,
            project_id=project_id,
            suite_version=suite_version,
            seed=seed,
            idempotency_key=idempotency_key,
            created_by=created_by,
        )
        with self._sessions.begin() as session:
            _require_active_tenant(session, context)
            return EvaluationRunRepository(session, context).create_idempotent(run)

    def get_run(
        self, context: TenantContext, run_id: str
    ) -> EvaluationRun | None:
        with self._sessions() as session:
            _require_active_tenant(session, context)
            return EvaluationRunRepository(session, context).get(run_id)

    def cancel_run(
        self, context: TenantContext, run_id: str, *, now: datetime | None = None
    ) -> bool:
        with self._sessions.begin() as session:
            _require_active_tenant(session, context)
            return EvaluationRunRepository(session, context).cancel(
                run_id, now=now or datetime.now(UTC)
            )

    def process_next(
        self,
        context: TenantContext,
        *,
        owner: str,
        now: datetime | None = None,
    ) -> EvaluationRun | None:
        started = now or datetime.now(UTC)
        with self._sessions.begin() as session:
            _require_active_tenant(session, context)
            repository = EvaluationRunRepository(session, context)
            claim = repository.claim_next(
                owner=owner, now=started, lease_seconds=300
            )
            if claim is None:
                return None
            if not repository.transition(
                claim, RunStatus.RUNNING, now=started + timedelta(milliseconds=1)
            ):
                return None
        self._worker_event("run_claimed", context, claim, stage="running")

        keys: list[str] = []
        stage = "running"
        try:
            benchmark = evaluate_task_benchmark(judge=StubLabJudge())
            generated_at = datetime.now(UTC)
            evidence = build_benchmark_evidence(
                benchmark,
                generated_at=generated_at.isoformat(),
                seed=claim.run.seed,
                lab_version=__version__,
            )
            payloads = {
                "json": (
                    json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8"),
                "markdown": render_benchmark_markdown(evidence).encode("utf-8"),
            }
            with self._sessions.begin() as session:
                _require_active_tenant(session, context)
                repository = EvaluationRunRepository(session, context)
                if not repository.transition(
                    claim, RunStatus.EVALUATING, now=generated_at
                ):
                    raise RuntimeError("run lease was lost before evaluation")
            stage = "evaluating"
            self._worker_event("run_stage", context, claim, stage=stage)

            artifacts: list[ReportArtifact] = []
            for format_name, data in payloads.items():
                artifact_id = new_id("art")
                key = build_artifact_key(
                    tenant_id=context.tenant_id,
                    run_id=claim.run.id,
                    artifact_id=artifact_id,
                    format=format_name,
                )
                size, digest = self._artifacts.put(key, data)
                keys.append(key)
                artifacts.append(
                    ReportArtifact(
                        id=artifact_id,
                        tenant_id=context.tenant_id,
                        run_id=claim.run.id,
                        format=format_name,
                        object_key=key,
                        sha256=digest,
                        size_bytes=size,
                        content_type=(
                            "application/json"
                            if format_name == "json"
                            else "text/markdown; charset=utf-8"
                        ),
                        created_at=generated_at,
                        expires_at=generated_at
                        + timedelta(days=self._retention_days),
                    )
                )

            with self._sessions.begin() as session:
                _require_active_tenant(session, context)
                artifact_repository = ReportArtifactRepository(session, context)
                for artifact in artifacts:
                    artifact_repository.add(artifact)
                run_repository = EvaluationRunRepository(session, context)
                if not run_repository.transition(
                    claim, RunStatus.COMPLETED, now=datetime.now(UTC)
                ):
                    raise RuntimeError("run lease was lost before completion")
                completed = run_repository.get(claim.run.id)
                if completed is None:
                    raise RuntimeError("completed run could not be reloaded")
            for artifact in artifacts:
                self._worker_event(
                    "artifact_committed",
                    context,
                    claim,
                    stage="completed",
                    artifact_id=artifact.id,
                    artifact_format=artifact.format,
                    artifact_sha256=artifact.sha256,
                    artifact_size_bytes=artifact.size_bytes,
                )
            self._worker_event(
                "run_completed", context, claim, stage="completed", result="success"
            )
            return completed
        except Exception as exc:
            for key in keys:
                self._artifacts.delete(key)
            # Only a category is logged; exception text may carry sensitive data.
            self._worker_event(
                "run_failed",
                context,
                claim,
                stage=stage,
                result=(
                    "tenant_denied"
                    if isinstance(exc, TenantAccessError)
                    else "error"
                ),
            )
            with self._sessions.begin() as session:
                repository = EvaluationRunRepository(session, context)
                current = repository.get(claim.run.id)
                if current and not current.status.terminal:
                    with contextlib.suppress(ValueError):
                        repository.transition(
                            claim, RunStatus.FAILED, now=datetime.now(UTC)
                        )
            raise

    def _worker_event(
        self,
        event: str,
        context: TenantContext,
        claim: LeaseClaim,
        **fields: object,
    ) -> None:
        extra: dict[str, object] = {
            "event": event,
            "run_id": claim.run.id,
            "worker_owner": claim.owner,
            "fencing_token": claim.fencing_token,
            "attempt": claim.run.attempt,
            **fields,
        }
        if self._audit_hasher is not None:
            extra["tenant_id_hash"] = self._audit_hasher.tenant(context.tenant_id)
            if claim.run.created_by is not None:
                extra["submitted_by_hash"] = self._audit_hasher.subject(
                    claim.run.created_by
                )
        self._logger.info(event, extra=extra)

    def read_report(
        self, context: TenantContext, run_id: str, format_name: str
    ) -> tuple[bytes, str] | None:
        with self._sessions() as session:
            _require_active_tenant(session, context)
            artifact = ReportArtifactRepository(session, context).get_for_run(
                run_id, format_name
            )
        if artifact is None:
            return None
        return (
            self._artifacts.read(
                artifact.object_key, expected_sha256=artifact.sha256
            ),
            artifact.content_type,
        )


def _require_active_tenant(session: Session, context: TenantContext) -> None:
    tenant = TenantRepository(session).get(context.tenant_id)
    if tenant is None or tenant.status != "active":
        raise TenantAccessError("tenant access denied")


__all__ = ["LabApplicationService"]
