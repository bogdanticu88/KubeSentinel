"""SQLite connection and schema for local snapshot storage.

One file, no server, fits a CLI tool that one operator runs from a laptop.
Snapshots live under the user's home directory by default, override with
KUBESENTINEL_HOME to point somewhere else, mainly useful for tests and for
a CI job that wants its own throwaway state directory rather than writing
into whatever machine happens to be running it.
"""

import os
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster TEXT NOT NULL,
    taken_at TEXT NOT NULL,
    is_baseline INTEGER NOT NULL DEFAULT 0,
    kubernetes_version TEXT,
    node_count INTEGER NOT NULL DEFAULT 0,
    score_overall INTEGER,
    resources_json TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    score_json TEXT NOT NULL,
    counts_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_cluster_taken_at
    ON snapshots (cluster, taken_at);
"""

# Columns added after a database's first CREATE TABLE already ran.
# CREATE TABLE IF NOT EXISTS does nothing for a table that already exists,
# an operator's existing local database from before a column existed would
# otherwise break the first time something tries to read it.
_ADDED_COLUMNS = {
    "is_audit": "INTEGER NOT NULL DEFAULT 0",
}


class StorageError(Exception):
    """Local snapshot storage could not be opened, read, or written."""


def default_state_dir() -> Path:
    override = os.environ.get("KUBESENTINEL_HOME")
    return Path(override) if override else Path.home() / ".kubesentinel"


def default_db_path() -> Path:
    return default_state_dir() / "kubesentinel.db"


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or default_db_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.executescript(_SCHEMA)
        _migrate(connection)
    except (OSError, sqlite3.Error) as error:
        raise StorageError(f"could not open snapshot storage at {path}: {error}") from error
    return connection


def _migrate(connection: sqlite3.Connection) -> None:
    existing_columns = {row["name"] for row in connection.execute("PRAGMA table_info(snapshots)")}
    for column, definition in _ADDED_COLUMNS.items():
        if column not in existing_columns:
            connection.execute(f"ALTER TABLE snapshots ADD COLUMN {column} {definition}")
    connection.commit()
