"""Transactional project/run use cases and offline benchmark worker."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, sessionmaker

from ai_agent_lab import __version__
from ai_agent_lab.benchmark_metrics import evaluate_task_benchmark
from ai_agent_lab.domain import (
    EvaluationRun,
    Project,
    ReportArtifact,
    RunStatus,
    TenantContext,
)
from ai_agent_lab.domain.entities import new_id
from ai_agent_lab.judge import StubLabJudge
from ai_agent_lab.report import (
    build_benchmark_evidence,
    render_benchmark_markdown,
)
from ai_agent_lab.storage.artifact_repository import ReportArtifactRepository
from ai_agent_lab.storage.artifact_store import ArtifactStore, build_artifact_key
from ai_agent_lab.storage.repositories import ProjectRepository
from ai_agent_lab.storage.run_repository import EvaluationRunRepository


class LabApplicationService:
    """Application boundary; HTTP and CLI adapters contain no business rules."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        artifacts: ArtifactStore,
        *,
        artifact_retention_days: int = 30,
    ) -> None:
        if not 1 <= artifact_retention_days <= 3650:
            raise ValueError("artifact retention must be between 1 and 3650 days")
        self._sessions = sessions
        self._artifacts = artifacts
        self._retention_days = artifact_retention_days

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
            ProjectRepository(session, context).add(project)
        return project

    def list_projects(self, context: TenantContext) -> tuple[Project, ...]:
        with self._sessions() as session:
            return ProjectRepository(session, context).list()

    def create_run(
        self,
        context: TenantContext,
        *,
        project_id: str,
        suite_version: str,
        seed: int,
        idempotency_key: str,
    ) -> tuple[EvaluationRun, bool]:
        run = EvaluationRun(
            id=new_id("run"),
            tenant_id=context.tenant_id,
            project_id=project_id,
            suite_version=suite_version,
            seed=seed,
            idempotency_key=idempotency_key,
        )
        with self._sessions.begin() as session:
            return EvaluationRunRepository(session, context).create_idempotent(run)

    def get_run(
        self, context: TenantContext, run_id: str
    ) -> EvaluationRun | None:
        with self._sessions() as session:
            return EvaluationRunRepository(session, context).get(run_id)

    def cancel_run(
        self, context: TenantContext, run_id: str, *, now: datetime | None = None
    ) -> bool:
        with self._sessions.begin() as session:
            return EvaluationRunRepository(session, context).cancel(
                run_id, now=now or datetime.now(timezone.utc)
            )

    def process_next(
        self,
        context: TenantContext,
        *,
        owner: str,
        now: datetime | None = None,
    ) -> EvaluationRun | None:
        started = now or datetime.now(timezone.utc)
        with self._sessions.begin() as session:
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

        keys: list[str] = []
        try:
            benchmark = evaluate_task_benchmark(judge=StubLabJudge())
            generated_at = datetime.now(timezone.utc)
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
                repository = EvaluationRunRepository(session, context)
                if not repository.transition(
                    claim, RunStatus.EVALUATING, now=generated_at
                ):
                    raise RuntimeError("run lease was lost before evaluation")

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
                artifact_repository = ReportArtifactRepository(session, context)
                for artifact in artifacts:
                    artifact_repository.add(artifact)
                run_repository = EvaluationRunRepository(session, context)
                if not run_repository.transition(
                    claim, RunStatus.COMPLETED, now=datetime.now(timezone.utc)
                ):
                    raise RuntimeError("run lease was lost before completion")
            return self.get_run(context, claim.run.id)
        except Exception:
            for key in keys:
                self._artifacts.delete(key)
            with self._sessions.begin() as session:
                repository = EvaluationRunRepository(session, context)
                current = repository.get(claim.run.id)
                if current and not current.status.terminal:
                    try:
                        repository.transition(
                            claim, RunStatus.FAILED, now=datetime.now(timezone.utc)
                        )
                    except ValueError:
                        pass
            raise

    def read_report(
        self, context: TenantContext, run_id: str, format_name: str
    ) -> tuple[bytes, str] | None:
        with self._sessions() as session:
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


__all__ = ["LabApplicationService"]
