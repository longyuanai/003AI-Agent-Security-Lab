"""FastAPI application factory with secure commercial defaults."""

from __future__ import annotations

import inspect
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ai_agent_lab import __version__
from ai_agent_lab.api.errors import APIError, error_envelope
from ai_agent_lab.api.schemas import (
    ErrorEnvelope,
    HealthResponse,
    ProjectCreate,
    ProjectResponse,
    RunCreate,
    RunResponse,
)
from ai_agent_lab.application import LabApplicationService
from ai_agent_lab.domain import EvaluationRun, Project, TenantContext
from ai_agent_lab.observability import MetricsRegistry


DEFAULT_MAX_REQUEST_BYTES = 1_048_576
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
ReadinessCheck = Callable[[], bool | Awaitable[bool]]


def create_app(
    *,
    readiness_check: ReadinessCheck | None = None,
    expose_docs: bool = False,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    metrics: MetricsRegistry | None = None,
    logger: logging.Logger | None = None,
    service: LabApplicationService | None = None,
    tenant_context: TenantContext | None = None,
    principal_id: str = "local_operator",
) -> FastAPI:
    """Create an API app; no benchmark or target execution occurs here."""

    if max_request_bytes < 1:
        raise ValueError("max_request_bytes must be positive")
    check = readiness_check or (lambda: True)
    active_metrics = metrics or MetricsRegistry()
    active_logger = logger or logging.getLogger("ai_agent_lab.api")
    app = FastAPI(
        title="AI Agent Security Lab API",
        version=__version__,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None,
    )

    @app.middleware("http")
    async def commercial_boundary(request: Request, call_next):
        started = time.perf_counter()
        request_id = _request_id(request.headers.get("x-request-id"))
        request.state.request_id = request_id
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                too_large = int(content_length) > max_request_bytes
            except ValueError:
                too_large = True
            if too_large:
                response = _error_response(
                    status_code=413,
                    code="request_too_large",
                    message="Request body exceeds the configured limit",
                    request_id=request_id,
                )
                return _observe_response(
                    request,
                    response,
                    request_id=request_id,
                    started=started,
                    metrics=active_metrics,
                    logger=active_logger,
                )
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - never expose internals to clients
            response = _error_response(
                status_code=500,
                code="internal_error",
                message="Internal server error",
                request_id=request_id,
            )
        return _observe_response(
            request,
            response,
            request_id=request_id,
            started=started,
            metrics=active_metrics,
            logger=active_logger,
        )

    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
        return _error_response(
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            request_id=_state_request_id(request),
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        issues = [
            {
                "location": [str(part) for part in error.get("loc", ())],
                "type": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
        ]
        return _error_response(
            status_code=422,
            code="validation_error",
            message="Request validation failed",
            request_id=_state_request_id(request),
            details={"issues": issues},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = {
            404: "not_found",
            405: "method_not_allowed",
        }.get(exc.status_code, "http_error")
        message = {
            404: "Resource was not found",
            405: "Method is not allowed",
        }.get(exc.status_code, "Request could not be completed")
        return _error_response(
            status_code=exc.status_code,
            code=code,
            message=message,
            request_id=_state_request_id(request),
        )

    @app.get(
        "/v1/health/live",
        response_model=HealthResponse,
        responses={500: {"model": ErrorEnvelope}},
        tags=["health"],
    )
    async def live() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    @app.get(
        "/v1/health/ready",
        response_model=HealthResponse,
        responses={503: {"model": ErrorEnvelope}},
        tags=["health"],
    )
    async def ready() -> HealthResponse:
        try:
            result = check()
            is_ready = await result if inspect.isawaitable(result) else result
        except Exception:  # noqa: BLE001 - dependency details are private
            is_ready = False
        if not is_ready:
            raise APIError(
                status_code=503,
                code="service_not_ready",
                message="Service dependencies are not ready",
            )
        return HealthResponse(status="ready", version=__version__)

    if service is not None and tenant_context is not None:

        @app.post(
            "/v1/projects",
            response_model=ProjectResponse,
            status_code=status.HTTP_201_CREATED,
            tags=["projects"],
        )
        def create_project(payload: ProjectCreate) -> ProjectResponse:
            try:
                project = service.create_project(
                    tenant_context,
                    name=payload.name,
                    created_by=principal_id,
                    target_policy=payload.target_policy,
                )
            except ValueError as exc:
                raise APIError(400, "invalid_project", str(exc)) from exc
            return _project_response(project)

        @app.get(
            "/v1/projects",
            response_model=list[ProjectResponse],
            tags=["projects"],
        )
        def list_projects() -> list[ProjectResponse]:
            return [
                _project_response(project)
                for project in service.list_projects(tenant_context)
            ]

        @app.post(
            "/v1/runs",
            response_model=RunResponse,
            status_code=status.HTTP_202_ACCEPTED,
            tags=["runs"],
        )
        def create_run(payload: RunCreate) -> RunResponse:
            try:
                run, _created = service.create_run(
                    tenant_context,
                    project_id=payload.project_id,
                    suite_version=payload.suite_version,
                    seed=payload.seed,
                    idempotency_key=payload.idempotency_key,
                )
            except ValueError as exc:
                raise APIError(404, "project_not_found", "Project was not found") from exc
            return _run_response(run)

        @app.get(
            "/v1/runs/{run_id}", response_model=RunResponse, tags=["runs"]
        )
        def get_run(run_id: str) -> RunResponse:
            run = service.get_run(tenant_context, run_id)
            if run is None:
                raise APIError(404, "run_not_found", "Evaluation run was not found")
            return _run_response(run)

        @app.post(
            "/v1/runs/{run_id}/cancel",
            response_model=RunResponse,
            tags=["runs"],
        )
        def cancel_run(run_id: str) -> RunResponse:
            if not service.cancel_run(tenant_context, run_id):
                raise APIError(409, "run_not_cancellable", "Run cannot be cancelled")
            run = service.get_run(tenant_context, run_id)
            assert run is not None
            return _run_response(run)

        @app.get("/v1/runs/{run_id}/reports/{format_name}", tags=["reports"])
        def download_report(run_id: str, format_name: str) -> Response:
            if format_name not in {"json", "markdown"}:
                raise APIError(404, "report_not_found", "Report was not found")
            result = service.read_report(tenant_context, run_id, format_name)
            if result is None:
                raise APIError(404, "report_not_found", "Report was not found")
            body, content_type = result
            return Response(content=body, media_type=content_type)

    return app


def _request_id(candidate: str | None) -> str:
    if candidate and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return f"req_{uuid.uuid4().hex}"


def _state_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", _request_id(None))


def _error_response(
    *,
    status_code: int,
    code: str,
    message: str,
    request_id: str,
    details: dict[str, Any] | Any | None = None,
) -> JSONResponse:
    safe_details = details if isinstance(details, dict) else {}
    return JSONResponse(
        status_code=status_code,
        content=error_envelope(
            code=code,
            message=message,
            request_id=request_id,
            details=safe_details,
        ),
    )


def _secure_response(response, request_id: str):
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def _project_response(project: Project) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        target_policy=dict(project.target_policy),
        version=project.version,
    )


def _run_response(run: EvaluationRun) -> RunResponse:
    return RunResponse(
        id=run.id,
        project_id=run.project_id,
        suite_version=run.suite_version,
        seed=run.seed,
        status=run.status.value,
        attempt=run.attempt,
        version=run.version,
    )


def _observe_response(
    request: Request,
    response,
    *,
    request_id: str,
    started: float,
    metrics: MetricsRegistry,
    logger: logging.Logger,
):
    duration_ms = max(0.0, (time.perf_counter() - started) * 1000)
    route_object = request.scope.get("route")
    route = getattr(route_object, "path", "unmatched")
    method = request.method.upper()
    metrics.observe_request(
        method=method,
        route=route,
        status_code=response.status_code,
        duration_ms=duration_ms,
    )
    logger.info(
        "http_request",
        extra={
            "event": "http_request",
            "request_id": request_id,
            "method": method,
            "route": route,
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 3),
            "result": "success" if response.status_code < 400 else "error",
        },
    )
    return _secure_response(response, request_id)


__all__ = ["DEFAULT_MAX_REQUEST_BYTES", "ReadinessCheck", "create_app"]
