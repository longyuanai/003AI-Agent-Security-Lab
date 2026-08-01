"""Versioned API boundary, error, privacy, and health tests."""

from __future__ import annotations

import asyncio

import httpx

from ai_agent_lab.api import create_app


class TestClient:
    """Small ASGI client that avoids deprecated third-party test adapters."""

    __test__ = False

    def __init__(self, app, *, raise_server_exceptions: bool = True) -> None:
        self._app = app
        self._raise = raise_server_exceptions

    def get(self, path: str, **kwargs):
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self._request("POST", path, **kwargs)

    def _request(self, method: str, path: str, **kwargs):
        async def send():
            transport = httpx.ASGITransport(
                app=self._app, raise_app_exceptions=self._raise
            )
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())


def test_live_health_is_public_minimal_and_secure() -> None:
    response = TestClient(create_app()).get("/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ai-agent-security-lab",
        "version": "0.1.0",
    }
    assert response.headers["x-request-id"].startswith("req_")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_ready_health_accepts_sync_and_async_checks() -> None:
    assert TestClient(create_app(readiness_check=lambda: True)).get(
        "/v1/health/ready"
    ).status_code == 200

    async def ready() -> bool:
        return True

    assert TestClient(create_app(readiness_check=ready)).get(
        "/v1/health/ready"
    ).json()["status"] == "ready"


def test_not_ready_uses_stable_503_envelope() -> None:
    response = TestClient(create_app(readiness_check=lambda: False)).get(
        "/v1/health/ready"
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_not_ready"
    assert response.json()["error"]["details"] == {}
    assert response.json()["error"]["request_id"] == response.headers[
        "x-request-id"
    ]


def test_readiness_exception_does_not_leak_dependency_details() -> None:
    def broken() -> bool:
        raise RuntimeError("postgres://user:secret@private-host/database")

    response = TestClient(create_app(readiness_check=broken)).get(
        "/v1/health/ready"
    )
    serialized = response.text.lower()
    assert response.status_code == 503
    assert "secret" not in serialized
    assert "private-host" not in serialized
    assert "runtimeerror" not in serialized


def test_safe_client_request_id_is_preserved() -> None:
    response = TestClient(create_app()).get(
        "/v1/health/live", headers={"X-Request-Id": "client-request_123"}
    )
    assert response.headers["x-request-id"] == "client-request_123"


def test_unsafe_client_request_id_is_replaced() -> None:
    response = TestClient(create_app()).get(
        "/v1/health/live",
        headers={"X-Request-Id": "bad\r\nInjected: value"},
    )
    request_id = response.headers["x-request-id"]
    assert request_id.startswith("req_")
    assert "Injected" not in request_id


def test_content_length_limit_fails_before_route_execution() -> None:
    response = TestClient(create_app(max_request_bytes=4)).get(
        "/v1/health/live", headers={"Content-Length": "5"}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_invalid_content_length_is_rejected() -> None:
    response = TestClient(create_app()).get(
        "/v1/health/live", headers={"Content-Length": "not-a-number"}
    )
    assert response.status_code == 413


def test_not_found_and_method_not_allowed_use_stable_errors() -> None:
    client = TestClient(create_app())
    missing = client.get("/v1/missing")
    wrong_method = client.post("/v1/health/live")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "method_not_allowed"


def test_validation_error_omits_rejected_input() -> None:
    app = create_app()

    @app.get("/v1/test/{number}")
    async def typed_path(number: int) -> dict[str, int]:
        return {"number": number}

    response = TestClient(app).get("/v1/test/API_KEY=fixture-secret")
    body = response.json()
    assert response.status_code == 422
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["details"]["issues"][0]["type"] == "int_parsing"
    assert "fixture-secret" not in response.text
    assert "input" not in body["error"]["details"]["issues"][0]


def test_unhandled_exception_is_generic_and_secret_free() -> None:
    app = create_app()

    @app.get("/v1/test/failure")
    async def failure() -> None:
        raise RuntimeError("API_KEY=fixture-secret C:/private/path")

    response = TestClient(app, raise_server_exceptions=False).get(
        "/v1/test/failure"
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "fixture-secret" not in response.text
    assert "private/path" not in response.text


def test_docs_are_disabled_by_default_and_explicitly_enabled() -> None:
    assert TestClient(create_app()).get("/docs").status_code == 404
    app = create_app(expose_docs=True)
    assert TestClient(app).get("/docs").status_code == 200
    schema = app.openapi()
    assert schema["info"]["title"] == "AI Agent Security Lab API"
    assert "/v1/health/live" in schema["paths"]
    assert "/v1/health/ready" in schema["paths"]


def test_invalid_max_request_size_fails_at_startup() -> None:
    try:
        create_app(max_request_bytes=0)
    except ValueError as exc:
        assert str(exc) == "max_request_bytes must be positive"
    else:
        raise AssertionError("invalid max request size was accepted")
