"""Artifact storage port and atomic local filesystem adapter."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Protocol


DEFAULT_MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
_KEY_PART = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class ArtifactIntegrityError(RuntimeError):
    pass


class ArtifactStore(Protocol):
    def put(self, key: str, data: bytes) -> tuple[int, str]: ...
    def read(self, key: str, *, expected_sha256: str | None = None) -> bytes: ...
    def delete(self, key: str) -> bool: ...


class FileArtifactStore:
    """Atomic local adapter; suitable for Community and single-host Preview."""

    def __init__(self, root: str | Path, *, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES):
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        root_path = Path(root)
        root_path.mkdir(parents=True, exist_ok=True)
        if root_path.is_symlink():
            raise ValueError("artifact root cannot be a symlink")
        self._root = root_path.resolve()
        self._max_bytes = max_bytes

    def put(self, key: str, data: bytes) -> tuple[int, str]:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        if len(data) > self._max_bytes:
            raise ValueError("artifact exceeds configured size limit")
        target = self._path(key, create_parent=True)
        if target.exists():
            raise FileExistsError("artifact key already exists")
        digest = hashlib.sha256(data).hexdigest()
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_name = temporary.name
            os.replace(temporary_name, target)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return len(data), digest

    def read(self, key: str, *, expected_sha256: str | None = None) -> bytes:
        target = self._path(key)
        data = target.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise ArtifactIntegrityError("artifact checksum mismatch")
        return data

    def delete(self, key: str) -> bool:
        target = self._path(key)
        try:
            target.unlink()
        except FileNotFoundError:
            return False
        return True

    def _path(self, key: str, *, create_parent: bool = False) -> Path:
        if "\\" in key:
            raise ValueError("artifact key must use POSIX separators")
        pure = PurePosixPath(key)
        if pure.is_absolute() or not pure.parts or any(
            part in {"", ".", ".."} or not _KEY_PART.fullmatch(part)
            for part in pure.parts
        ):
            raise ValueError("invalid artifact key")
        target = self._root
        for index, part in enumerate(pure.parts):
            target = target / part
            if target.exists() and target.is_symlink():
                raise ValueError("artifact path contains a symlink")
            if create_parent and index < len(pure.parts) - 1:
                target.mkdir(exist_ok=True)
        resolved = target.resolve(strict=False)
        if not resolved.is_relative_to(self._root):
            raise ValueError("artifact key escapes storage root")
        return resolved


def build_artifact_key(
    *, tenant_id: str, run_id: str, artifact_id: str, format: str
) -> str:
    """Generate a bounded server-side key from validated identifiers."""

    extension = {"json": "json", "markdown": "md"}.get(format)
    if extension is None:
        raise ValueError("artifact format must be json or markdown")
    for value in (tenant_id, run_id, artifact_id):
        if not _KEY_PART.fullmatch(value):
            raise ValueError("artifact key identifier is invalid")
    return f"{tenant_id}/{run_id}/{artifact_id}.{extension}"


__all__ = [
    "ArtifactIntegrityError",
    "ArtifactStore",
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "FileArtifactStore",
    "build_artifact_key",
]
