from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest

from ojas_reconciler.db2_behavior.governance.adapters.sqlite import (
    GovernanceStore,
    GovernanceStoreError,
)

NOW = "2026-07-29T15:00:00Z"


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _write_manifest(directory: Path, migrations: list[dict[str, str | None]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(
        json.dumps({"schema_version": "test", "migrations": migrations}, indent=2),
        encoding="utf-8",
    )


def test_failed_migration_rolls_back_schema_and_ledger(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    first = migrations / "0001.sql"
    second = migrations / "0002.sql"
    migrations.mkdir()
    first.write_text(
        """
        CREATE TABLE governance_schema_migrations (
          migration_id TEXT PRIMARY KEY,
          migration_digest TEXT NOT NULL,
          previous_migration_digest TEXT,
          applied_at TEXT NOT NULL
        );
        CREATE TABLE governance_artifacts (
          artifact_id TEXT PRIMARY KEY,
          artifact_type TEXT NOT NULL,
          artifact_ref TEXT NOT NULL,
          content_digest TEXT NOT NULL,
          payload_digest TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          behavior_id TEXT,
          source_symbol_id TEXT,
          symbol_lineage_id TEXT,
          artifact_revision_id TEXT,
          parent_artifact_id TEXT,
          invalidates_machine_attestation INTEGER NOT NULL DEFAULT 0,
          platform_governance_ref TEXT,
          authority_scope TEXT NOT NULL DEFAULT 'LOCAL_NON_AUTHORITATIVE_EVIDENCE',
          created_at TEXT NOT NULL
        );
        """,
        encoding="utf-8",
    )
    first_digest = _digest(first)
    _write_manifest(
        migrations,
        [
            {
                "migration_id": "0001",
                "filename": first.name,
                "digest": first_digest,
                "previous_migration_digest": None,
            }
        ],
    )
    database = tmp_path / "atomic.sqlite3"
    GovernanceStore(database, migrations).initialize(applied_at=NOW)

    second.write_text(
        """
        ALTER TABLE governance_artifacts
          ADD COLUMN migration_marker TEXT;
        INSERT INTO table_that_does_not_exist(value) VALUES ('force rollback');
        """,
        encoding="utf-8",
    )
    _write_manifest(
        migrations,
        [
            {
                "migration_id": "0001",
                "filename": first.name,
                "digest": first_digest,
                "previous_migration_digest": None,
            },
            {
                "migration_id": "0002",
                "filename": second.name,
                "digest": _digest(second),
                "previous_migration_digest": first_digest,
            },
        ],
    )

    with pytest.raises(sqlite3.OperationalError, match="table_that_does_not_exist"):
        GovernanceStore(database, migrations).initialize(applied_at=NOW)

    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(governance_artifacts)")}
        applied = [row[0] for row in connection.execute(
            "SELECT migration_id FROM governance_schema_migrations ORDER BY rowid"
        )]
    assert "migration_marker" not in columns
    assert applied == ["0001"]


def test_unknown_applied_migration_is_rejected(tmp_path: Path) -> None:
    store = GovernanceStore(tmp_path / "unknown.sqlite3")
    store.initialize(applied_at=NOW)
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "INSERT INTO governance_schema_migrations VALUES (?, ?, ?, ?)",
            ("9999_unknown", "sha256:unknown", "sha256:unknown", NOW),
        )
    with pytest.raises(GovernanceStoreError, match="Unknown applied migration"):
        store.initialize(applied_at=NOW)


def test_non_contiguous_applied_prefix_is_rejected(tmp_path: Path) -> None:
    store = GovernanceStore(tmp_path / "prefix.sqlite3")
    store.initialize(applied_at=NOW)
    with sqlite3.connect(store.database) as connection:
        connection.execute("DELETE FROM governance_schema_migrations WHERE migration_id = '0001_initial'")
    with pytest.raises(GovernanceStoreError, match="contiguous manifest prefix"):
        store.initialize(applied_at=NOW)


def test_migration_transaction_control_is_rejected(tmp_path: Path) -> None:
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    script = migrations / "0001.sql"
    script.write_text("BEGIN; CREATE TABLE x(id INTEGER); COMMIT;", encoding="utf-8")
    _write_manifest(
        migrations,
        [{
            "migration_id": "0001",
            "filename": script.name,
            "digest": _digest(script),
            "previous_migration_digest": None,
        }],
    )
    with pytest.raises(GovernanceStoreError, match="transaction control"):
        GovernanceStore(tmp_path / "tx.sqlite3", migrations).initialize(applied_at=NOW)


def test_connect_does_not_negotiate_wal_before_initialization(tmp_path: Path) -> None:
    database = tmp_path / "connect-is-read-only.sqlite3"
    store = GovernanceStore(database)

    connection = store.connect()
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"
    finally:
        connection.close()

    store.initialize(applied_at=NOW)
    with sqlite3.connect(database) as initialized:
        assert initialized.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_concurrent_initialization_serializes(tmp_path: Path) -> None:
    database = tmp_path / "concurrent.sqlite3"

    def initialize(index: int) -> None:
        GovernanceStore(database).initialize(applied_at=f"{NOW}:{index}")

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(initialize, range(4)))

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT migration_id, COUNT(*) FROM governance_schema_migrations "
            "GROUP BY migration_id ORDER BY migration_id"
        ).fetchall()
    assert rows == [
        ("0001_initial", 1),
        ("0002_local_non_authoritative_scope", 1),
    ]
