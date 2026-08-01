"""Verified SQLite backup/restore for local single-host deployments."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class BackupManifest:
    path: Path
    sha256: str
    size_bytes: int
    created_at: datetime


def backup_sqlite(source: str | Path, output: str | Path) -> BackupManifest:
    """Create a transactionally consistent backup and verify integrity."""

    source_path = _existing_regular_file(source, "source database")
    output_path = Path(output)
    if output_path.exists() or output_path.is_symlink():
        raise FileExistsError("backup output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if source_path == output_path.resolve(strict=False):
        raise ValueError("backup output must differ from source")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
        source_connection = sqlite3.connect(
            f"file:{source_path.as_posix()}?mode=ro", uri=True
        )
        destination_connection = sqlite3.connect(temporary_name)
        try:
            source_connection.backup(destination_connection)
            if destination_connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("backup failed SQLite integrity check")
        finally:
            destination_connection.close()
            source_connection.close()
        with open(temporary_name, "r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary_name, output_path)
        temporary_name = None
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return _manifest(output_path)


def verify_sqlite_backup(
    backup: str | Path, *, expected_sha256: str | None = None
) -> BackupManifest:
    path = _existing_regular_file(backup, "backup")
    manifest = _manifest(path)
    if expected_sha256 and manifest.sha256 != expected_sha256:
        raise ValueError("backup checksum mismatch")
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("backup failed SQLite integrity check")
    finally:
        connection.close()
    return manifest


def restore_sqlite_backup(
    backup: str | Path,
    target: str | Path,
    *,
    expected_sha256: str,
) -> BackupManifest:
    """Restore only to a new path; never overwrite a live database."""

    manifest = verify_sqlite_backup(backup, expected_sha256=expected_sha256)
    target_path = Path(target)
    if target_path.exists() or target_path.is_symlink():
        raise FileExistsError("restore target already exists")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=target_path.parent,
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
        shutil.copyfile(manifest.path, temporary_name)
        with open(temporary_name, "r+b") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary_name, target_path)
        temporary_name = None
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return verify_sqlite_backup(target_path, expected_sha256=expected_sha256)


def _existing_regular_file(value: str | Path, label: str) -> Path:
    raw = Path(value)
    if raw.is_symlink() or not raw.is_file():
        raise ValueError(f"{label} must be an existing regular file")
    return raw.resolve()


def _manifest(path: Path) -> BackupManifest:
    data = path.read_bytes()
    return BackupManifest(
        path=path.resolve(),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        created_at=datetime.now(timezone.utc),
    )


__all__ = [
    "BackupManifest",
    "backup_sqlite",
    "restore_sqlite_backup",
    "verify_sqlite_backup",
]
