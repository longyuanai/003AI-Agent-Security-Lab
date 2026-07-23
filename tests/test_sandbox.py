"""Tests for the standard-library subprocess sandbox."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_agent_lab.cli import cli
from ai_agent_lab.sandbox import (
    Sandbox,
    SandboxPolicy,
    SandboxTimeout,
    SandboxViolation,
)


def _sandbox(tmp_path: Path, **policy_kwargs) -> Sandbox:
    return Sandbox(
        SandboxPolicy(base_dir=tmp_path / "sandboxes", **policy_kwargs)
    )


def test_sandbox_runs_python_and_captures_output(tmp_path: Path):
    result = _sandbox(tmp_path).run_python("print('sandbox-ok')")
    assert result.succeeded
    assert result.stdout.strip() == "sandbox-ok"
    assert result.latency_ms >= 0


def test_sandbox_environment_uses_allowlist(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LAB_VISIBLE", "yes")
    monkeypatch.setenv("LAB_SECRET", "must-not-leak")
    result = _sandbox(tmp_path, allowed_env=("LAB_VISIBLE",)).run_python(
        "import os; print(os.getenv('LAB_VISIBLE'), os.getenv('LAB_SECRET'))"
    )
    assert result.stdout.strip() == "yes None"


def test_sandbox_blocks_network_with_syscall_name(tmp_path: Path):
    with pytest.raises(SandboxViolation, match="blocked syscall: socket") as exc:
        _sandbox(tmp_path).run_python("import socket; socket.socket()")
    assert exc.value.syscall == "socket"


def test_sandbox_can_optionally_allow_network_object_creation(tmp_path: Path):
    result = _sandbox(tmp_path, allow_network=True).run_python(
        "import socket; sock = socket.socket(); sock.close(); print('socket-ok')"
    )
    assert result.succeeded
    assert result.stdout.strip() == "socket-ok"


def test_sandbox_blocks_writes_outside_temp_dir(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    code = f"open({str(outside)!r}, 'w').write('blocked')"
    with pytest.raises(SandboxViolation, match="blocked syscall: open") as exc:
        _sandbox(tmp_path).run_python(code)
    assert exc.value.syscall == "open"
    assert not outside.exists()


def test_sandbox_allows_writes_inside_temp_dir(tmp_path: Path):
    result = _sandbox(tmp_path).run_python(
        "from pathlib import Path; Path('inside.txt').write_text('ok'); "
        "print(Path('inside.txt').read_text())"
    )
    assert result.succeeded
    assert result.stdout.strip() == "ok"


def test_sandbox_kills_process_after_timeout(tmp_path: Path):
    with pytest.raises(SandboxTimeout, match="wait_timeout") as exc:
        _sandbox(tmp_path, timeout_s=0.05).run_python(
            "import time; time.sleep(2)"
        )
    assert exc.value.syscall == "wait_timeout"


def test_sandbox_returns_ordinary_python_failure(tmp_path: Path):
    result = _sandbox(tmp_path).run_python("raise ValueError('lab failure')")
    assert not result.succeeded
    assert "ValueError: lab failure" in result.stderr


def test_cli_sandbox_smoke():
    result = CliRunner().invoke(
        cli,
        ["sandbox", "--code", "print('cli-sandbox-ok')", "--timeout", "1"],
    )
    assert result.exit_code == 0, result.output
    assert "cli-sandbox-ok" in result.output
    assert "Sandbox OK" in result.output
