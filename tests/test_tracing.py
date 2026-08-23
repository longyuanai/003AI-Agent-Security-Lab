from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ai_agent_lab import scan


def test_scan_entrypoint_creates_span(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object],
    ) -> Iterator[None]:
        captured.append((name, attributes))
        yield

    expected = {"findings": []}
    monkeypatch.setattr(scan, "span", recording_span)
    monkeypatch.setattr(scan, "_scan_payload", lambda _payload, **_kwargs: expected)

    assert scan.scan_payload({"attack": "private-payload"}) is expected
    assert captured == [
        (
            "product.scan",
            {"product.id": "003", "scan.target_type": "atlas_scenario"},
        )
    ]
