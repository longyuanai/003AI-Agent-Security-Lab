"""Real localhost IntegrationGateway → LabAdapter → CLI tests."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUITE_ROOT = PROJECT_ROOT.parent
INTEGRATION_ROOT = SUITE_ROOT / "000shared-integration"
CORE_ROOT = SUITE_ROOT / "000shared-llm-core"
@pytest.fixture(scope="module")
def gateway_url() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    pythonpath = [
        str(INTEGRATION_ROOT / "src"),
        str(CORE_ROOT / "src"),
    ]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    env["LLM_PROVIDER"] = "fake"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "shared_integration.gateway:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=INTEGRATION_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_gateway(process, url)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_post_scan_returns_findings(gateway_url: str) -> None:
    response = _request_json(
        f"{gateway_url}/v0.5/003/scan",
        method="POST",
        payload={
            "agent": "sql_assistant",
            "attack": "indirect_injection",
            "iterations": 1,
        },
    )

    assert response["source"] == "003"
    assert response["count"] == 1
    finding = response["findings"][0]
    assert finding["title"] == "SQL injection via indirect prompt injection"
    assert finding["description"].endswith("ASR=1/1")
    assert finding["metadata"]["llm_provider"] == "fake"


def test_health_endpoint_reports_lab_ok(gateway_url: str) -> None:
    response = _request_json(f"{gateway_url}/v0.5/health")
    assert response["status"] == "ok"
    assert response["products"]["003"]["status"] == "ok"
    assert response["products"]["003"]["available"] is True
    assert all(
        product["status"] == "ok" for product in response["products"].values()
    )


def test_gateway_registry_contains_lab_finding(gateway_url: str) -> None:
    response = _request_json(f"{gateway_url}/v0.5/findings?source=003")
    assert response["count"] >= 1
    assert response["findings"][0]["source"] == "003"


def _wait_for_gateway(process: subprocess.Popen[bytes], gateway_url: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"gateway exited early with code {process.returncode}")
        try:
            _request_json(f"{gateway_url}/v0.5/health")
            return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    pytest.fail(f"gateway did not become ready at {gateway_url} within 15 seconds")


def _request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))
