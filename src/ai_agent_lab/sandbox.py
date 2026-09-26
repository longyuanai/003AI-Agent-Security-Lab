"""Best-effort subprocess sandbox for deterministic Code-Act exercises.

The PoC uses only the Python standard library. Each execution receives:

* a fresh ``sandbox_*`` temporary working directory;
* an explicit environment-variable allowlist;
* Python-level guards for network sockets and writes outside the temp dir,
  including relinking (``os.rename`` / ``replace`` / ``link`` / ``symlink``)
  and the low-level ``_socket`` module;
* a hard subprocess timeout followed by ``kill()``.

These guards make lab failures deterministic and observable. They are not a
replacement for Docker, gVisor, seccomp, or another kernel isolation boundary.
On Windows the timeout intentionally degrades to killing the direct subprocess.

Known limitations, deliberately not fixed because in-process monkeypatching
cannot reach them -- both are pinned by tests in ``tests/test_sandbox.py`` so
the boundary stays honest:

* a spawned child process does not inherit the guards;
* ``ctypes`` calls into C underneath every Python-level guard.

Treat this as a determinism aid for the lab, not as containment for untrusted
code.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_BLOCKED_MARKER = "SANDBOX_BLOCKED:"
_PLATFORM_ENV = ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP")
_BLOCKED_PATTERN = re.compile(r"SANDBOX_BLOCKED:(?P<syscall>[a-zA-Z0-9_.-]+)")


class SandboxError(RuntimeError):
    """Base error for sandbox policy and execution failures."""


class SandboxViolation(SandboxError):
    """Raised when a guarded operation is attempted."""

    def __init__(self, syscall: str, detail: str = "") -> None:
        self.syscall = syscall
        self.detail = detail
        message = f"sandbox blocked syscall: {syscall}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


class SandboxTimeout(SandboxError):
    """Raised after the sandbox kills a process that exceeded its deadline."""

    def __init__(self, timeout_s: float) -> None:
        self.syscall = "wait_timeout"
        self.timeout_s = timeout_s
        super().__init__(
            f"sandbox blocked syscall: wait_timeout "
            f"(process killed after {timeout_s:g}s)"
        )


@dataclass(frozen=True)
class SandboxPolicy:
    """Configuration for one or more isolated Python executions."""

    timeout_s: float = 2.0
    allowed_env: tuple[str, ...] = ()
    allow_network: bool = False
    read_only_filesystem: bool = True
    base_dir: Path | None = None

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be greater than zero")


@dataclass(frozen=True)
class SandboxResult:
    """Captured result of a completed sandbox subprocess."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    latency_ms: int

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "latency_ms": self.latency_ms,
            "succeeded": self.succeeded,
        }


@dataclass
class Sandbox:
    """Execute Python snippets in a fresh, guarded subprocess."""

    policy: SandboxPolicy = SandboxPolicy()

    def run_python(
        self,
        code: str,
        *,
        env: Mapping[str, str] | None = None,
    ) -> SandboxResult:
        """Run ``code`` under the configured policy.

        A policy violation raises :class:`SandboxViolation`; a deadline breach
        raises :class:`SandboxTimeout`. Ordinary Python errors are returned in
        ``SandboxResult`` with a non-zero return code.
        """

        if not isinstance(code, str) or not code.strip():
            raise ValueError("code must be a non-empty string")

        base_dir = self.policy.base_dir
        if base_dir is not None:
            base_dir = Path(base_dir)
            base_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            prefix="sandbox_",
            dir=str(base_dir) if base_dir is not None else None,
        ) as sandbox_dir:
            bootstrap = self._build_bootstrap(code)
            command = (sys.executable, "-I", "-c", bootstrap)
            return self._run_subprocess(
                command,
                cwd=Path(sandbox_dir),
                env=self._filtered_env(env),
            )

    def _filtered_env(
        self,
        extra_env: Mapping[str, str] | None,
    ) -> dict[str, str]:
        allowed = {name.upper() for name in (*_PLATFORM_ENV, *self.policy.allowed_env)}
        candidates = dict(os.environ)
        if extra_env:
            candidates.update({str(key): str(value) for key, value in extra_env.items()})

        filtered = {
            key: value
            for key, value in candidates.items()
            if key.upper() in allowed
        }
        filtered["PYTHONDONTWRITEBYTECODE"] = "1"
        filtered["PYTHONIOENCODING"] = "utf-8"
        return filtered

    def _run_subprocess(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str],
    ) -> SandboxResult:
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        started = time.perf_counter()
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        try:
            stdout, stderr = process.communicate(timeout=self.policy.timeout_s)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise SandboxTimeout(self.policy.timeout_s) from exc

        latency_ms = max(0, round((time.perf_counter() - started) * 1000))
        marker = _BLOCKED_PATTERN.search(stderr)
        if marker:
            raise SandboxViolation(marker.group("syscall"), stderr.strip())

        return SandboxResult(
            command=command,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            latency_ms=latency_ms,
        )

    def _build_bootstrap(self, code: str) -> str:
        guards: list[str] = []
        if self.policy.read_only_filesystem:
            guards.append(
                """
                import builtins as _sandbox_builtins
                import io as _sandbox_io
                import os as _sandbox_os
                from pathlib import Path as _SandboxPath

                _sandbox_root = _SandboxPath.cwd().resolve()
                _sandbox_real_open = _sandbox_builtins.open
                _sandbox_real_os_open = _sandbox_os.open

                def _sandbox_guard_write(path):
                    if isinstance(path, int):
                        return
                    resolved = _SandboxPath(path).resolve()
                    if resolved != _sandbox_root and _sandbox_root not in resolved.parents:
                        raise PermissionError("SANDBOX_BLOCKED:open")

                def _sandbox_open(file, mode="r", *args, **kwargs):
                    if any(flag in mode for flag in "wax+"):
                        _sandbox_guard_write(file)
                    return _sandbox_real_open(file, mode, *args, **kwargs)

                def _sandbox_os_open(path, flags, *args, **kwargs):
                    write_flags = (
                        _sandbox_os.O_WRONLY | _sandbox_os.O_RDWR |
                        _sandbox_os.O_CREAT | _sandbox_os.O_TRUNC |
                        _sandbox_os.O_APPEND
                    )
                    if flags & write_flags:
                        _sandbox_guard_write(path)
                    return _sandbox_real_os_open(path, flags, *args, **kwargs)

                # Relinking is a write. Guarding only open() let a file be
                # created inside the sandbox and then moved out with
                # os.replace(), which defeats the point of the write guard.
                def _sandbox_guard_relink(name):
                    _real = getattr(_sandbox_os, name)

                    def _guarded(src, dst, *args, **kwargs):
                        _sandbox_guard_write(dst)
                        return _real(src, dst, *args, **kwargs)

                    return _guarded

                _sandbox_builtins.open = _sandbox_open
                _sandbox_io.open = _sandbox_open
                _sandbox_os.open = _sandbox_os_open
                for _name in ("rename", "replace", "link", "symlink"):
                    if hasattr(_sandbox_os, _name):
                        setattr(_sandbox_os, _name, _sandbox_guard_relink(_name))
                """
            )
        if not self.policy.allow_network:
            guards.append(
                """
                import socket as _sandbox_socket

                def _sandbox_block_socket(*args, **kwargs):
                    raise PermissionError("SANDBOX_BLOCKED:socket")

                _sandbox_socket.socket = _sandbox_block_socket
                _sandbox_socket.create_connection = _sandbox_block_socket
                # `socket` is a thin wrapper over the C module; patching only
                # the wrapper left `import _socket; _socket.socket()` open.
                try:
                    import _socket as _sandbox_c_socket
                except ImportError:
                    pass
                else:
                    _sandbox_c_socket.socket = _sandbox_block_socket
                """
            )

        guard_source = "\n".join(textwrap.dedent(part) for part in guards)
        return (
            f"{guard_source}\n"
            f"_SANDBOX_USER_CODE = {code!r}\n"
            "exec(compile(_SANDBOX_USER_CODE, '<sandbox>', 'exec'), "
            "{'__name__': '__main__'})\n"
        )
