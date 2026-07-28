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


# --------------------------------------------------------------------- #
# Escape vectors                                                        #
#                                                                       #
# The guards are in-process monkeypatches, so their reach is limited by #
# construction. The tests below split that boundary in two: vectors the #
# guard claims to cover (and must), and vectors it cannot reach. The    #
# second group asserts today's permissive behaviour on purpose -- if a  #
# real kernel boundary ever lands, these fail and force the docs and    #
# the README's "not a security boundary" wording to be revisited.       #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "code"),
    [
        # Each of these moved a file out of the sandbox before being guarded:
        # writing inside the temp dir and then relinking the result out.
        ("os.replace", "import os; open('a','w').write('x'); os.replace('a', {dst!r})"),
        ("os.rename", "import os; open('a','w').write('x'); os.rename('a', {dst!r})"),
        (
            "shutil.move",
            "import shutil; open('a','w').write('x'); shutil.move('a', {dst!r})",
        ),
    ],
)
def test_relinking_cannot_move_a_file_out_of_the_sandbox(
    tmp_path: Path, name: str, code: str
):
    escape = tmp_path / "escaped.txt"
    with pytest.raises(SandboxViolation):
        _sandbox(tmp_path).run_python(code.format(dst=str(escape)))
    assert not escape.exists(), f"{name} escaped the sandbox"


def test_low_level_socket_module_is_blocked_too(tmp_path: Path):
    # `socket` is a thin wrapper over the C module, so patching only the
    # wrapper left `import _socket` as an open door.
    with pytest.raises(SandboxViolation) as excinfo:
        _sandbox(tmp_path).run_python("import _socket; _socket.socket()")
    assert excinfo.value.syscall == "socket"


def test_known_limitation_child_processes_are_unguarded(tmp_path: Path):
    """A spawned process does not inherit the in-process guards.

    Documented, not fixed: stopping this needs an OS-level boundary.
    """
    result = _sandbox(tmp_path, timeout_s=20).run_python(
        "import subprocess, sys;"
        "print(subprocess.run([sys.executable,'-c','print(42)'],"
        "capture_output=True,text=True).stdout.strip())"
    )
    assert result.succeeded
    assert "42" in result.stdout


def test_known_limitation_ctypes_can_reach_libc(tmp_path: Path):
    """ctypes calls C directly, underneath every Python-level guard.

    Documented, not fixed: same reason as above.
    """
    result = _sandbox(tmp_path).run_python(
        "import ctypes; print(ctypes.CDLL(None) is not None)"
    )
    assert result.succeeded
    assert result.stdout.strip() == "True"
