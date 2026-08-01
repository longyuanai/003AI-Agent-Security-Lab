"""FastAPI application factory with secure commercial defaults."""

from __future__ import annotations

import inspect
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ai_agent_lab import __version__
from ai_agent_lab.api.errors import APIError, error_envelope
from ai_agent_lab.api.schemas import ErrorEnvelope, HealthResponse
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
