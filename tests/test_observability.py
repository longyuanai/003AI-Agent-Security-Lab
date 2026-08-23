"""Privacy-safe logs, metrics, and API instrumentation tests."""

from __future__ import annotations

import asyncio
import io
import json
import logging

import httpx
import pytest

from ai_agent_lab.api import create_app
from ai_agent_lab.observability import (
    MetricsRegistry,
    SafeJSONFormatter,
    configure_json_logging,
    tenant_hash,
)


def _request(app, path: str, *, method: str = "GET"):
    async def send():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.request(method, path)

    return asyncio.run(send())


def test_json_formatter_emits_only_allowlisted_fields() -> None:
    record = logging.LogRecord(
        "fixture", logging.INFO, __file__, 1, "API_KEY=secret", (), None
    )
    record.event = "fixture_event"
    record.request_id = "req_fixture"
    record.authorization = "Bearer secret"
    record.user_input = "raw prompt"
    payload = json.loads(SafeJSONFormatter().format(record))
    assert payload["event"] == "fixture_event"
    assert payload["request_id"] == "req_fixture"
    serialized = json.dumps(payload).lower()
    assert "secret" not in serialized
    assert "raw prompt" not in serialized
    assert "authorization" not in serialized


def test_configure_logging_does_not_mutate_root_or_duplicate_handlers() -> None:
    root_handlers = tuple(logging.getLogger().handlers)
    stream = io.StringIO()
    logger = configure_json_logging(stream=stream)
    logger = configure_json_logging(stream=stream)
    assert len(logger.handlers) == 1
    assert tuple(logging.getLogger().handlers) == root_handlers


def test_tenant_hash_is_salted_stable_and_non_reversible_label() -> None:
    first = tenant_hash("tenant-a", salt="deployment-a")
    assert first == tenant_hash("tenant-a", salt="deployment-a")
    assert first != tenant_hash("tenant-a", salt="deployment-b")
    assert "tenant" not in first
    with pytest.raises(ValueError):
        tenant_hash("tenant-a", salt="")


def test_metrics_registry_counts_status_and_duration() -> None:
    registry = MetricsRegistry()
    registry.observe_request(
        method="get", route="/v1/health/live", status_code=200, duration_ms=2.5
    )
    registry.observe_request(
        method="GET", route="/v1/health/live", status_code=200, duration_ms=1.5
    )
    snapshot = registry.snapshot()
    assert snapshot.requests_total[("GET", "/v1/health/live", 200)] == 2
    assert snapshot.request_duration_ms_total[("GET", "/v1/health/live")] == 4.0
    assert snapshot.request_duration_count[("GET", "/v1/health/live")] == 2


def test_metrics_registry_rejects_negative_duration() -> None:
    with pytest.raises(ValueError, match="negative"):
        MetricsRegistry().observe_request(
            method="GET", route="/", status_code=200, duration_ms=-1
        )


def test_api_records_route_template_and_status_without_raw_url() -> None:
    registry = MetricsRegistry()
    stream = io.StringIO()
    logger = logging.Logger("fixture")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    app = create_app(metrics=registry, logger=logger)
    response = _request(app, "/v1/health/live?API_KEY=fixture-secret")
    assert response.status_code == 200
    snapshot = registry.snapshot()
    assert snapshot.requests_total[("GET", "/v1/health/live", 200)] == 1
    log = stream.getvalue()
    assert "/v1/health/live" in log
    assert "fixture-secret" not in log
    assert "api_key" not in log.lower()


def test_unmatched_route_does_not_log_attacker_controlled_path() -> None:
    stream = io.StringIO()
    logger = logging.Logger("fixture-unmatched")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    response = _request(
        create_app(logger=logger), "/API_KEY=fixture-secret/raw-prompt"
    )
    assert response.status_code == 404
    payload = json.loads(stream.getvalue())
    assert payload["route"] == "unmatched"
    assert "fixture-secret" not in stream.getvalue()
    assert "raw-prompt" not in stream.getvalue()


def test_not_ready_is_counted_and_logged_as_error() -> None:
    registry = MetricsRegistry()
    stream = io.StringIO()
    logger = logging.Logger("fixture-ready")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    response = _request(
        create_app(readiness_check=lambda: False, metrics=registry, logger=logger),
        "/v1/health/ready",
    )
    assert response.status_code == 503
    assert registry.snapshot().requests_total[("GET", "/v1/health/ready", 503)] == 1
    assert json.loads(stream.getvalue())["result"] == "error"


def test_request_id_correlates_response_and_log() -> None:
    stream = io.StringIO()
    logger = logging.Logger("fixture-correlation")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJSONFormatter())
    logger.addHandler(handler)
    response = _request(create_app(logger=logger), "/v1/health/live")
    assert json.loads(stream.getvalue())["request_id"] == response.headers[
        "x-request-id"
    ]
