"""Local backup, integrity, and non-destructive recovery tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ai_agent_lab.operations import (
    backup_sqlite,
    restore_sqlite_backup,
    verify_sqlite_backup,
)


def _database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE fixture (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO fixture(value) VALUES ('durable')")
        connection.commit()
    finally:
        connection.close()


def test_backup_and_restore_preserve_committed_data(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backups" / "source.backup.db"
    restored = tmp_path / "restore" / "restored.db"
    _database(source)
    manifest = backup_sqlite(source, backup)
    restored_manifest = restore_sqlite_backup(
        backup, restored, expected_sha256=manifest.sha256
    )
    assert restored_manifest.sha256 == manifest.sha256
    connection = sqlite3.connect(restored)
    try:
        assert connection.execute("SELECT value FROM fixture").fetchone()[0] == (
            "durable"
        )
    finally:
        connection.close()


def test_backup_manifest_has_checksum_size_and_aware_time(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    _database(source)
    manifest = backup_sqlite(source, tmp_path / "backup.db")
    assert len(manifest.sha256) == 64
    assert manifest.size_bytes > 0
    assert manifest.created_at.tzinfo is not None
    assert verify_sqlite_backup(
        manifest.path, expected_sha256=manifest.sha256
    ).sha256 == manifest.sha256


def test_restore_refuses_to_overwrite_existing_target(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    target = tmp_path / "live.db"
    _database(source)
    _database(target)
    manifest = backup_sqlite(source, backup)
    with pytest.raises(FileExistsError, match="already exists"):
        restore_sqlite_backup(backup, target, expected_sha256=manifest.sha256)


def test_backup_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    output = tmp_path / "backup.db"
    _database(source)
    output.write_bytes(b"do-not-overwrite")
    with pytest.raises(FileExistsError):
        backup_sqlite(source, output)
    assert output.read_bytes() == b"do-not-overwrite"


def test_checksum_mismatch_blocks_restore(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _database(source)
    backup_sqlite(source, backup)
    with pytest.raises(ValueError, match="checksum"):
        restore_sqlite_backup(
            backup, tmp_path / "restored.db", expected_sha256="0" * 64
        )
    assert not (tmp_path / "restored.db").exists()


def test_backup_rejects_missing_or_symlink_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        backup_sqlite(tmp_path / "missing.db", tmp_path / "backup.db")
    source = tmp_path / "source.db"
    link = tmp_path / "source-link.db"
    _database(source)
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are not available for this Windows account")
    with pytest.raises(ValueError, match="regular file"):
        backup_sqlite(link, tmp_path / "backup.db")
