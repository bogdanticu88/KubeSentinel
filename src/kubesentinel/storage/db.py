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
    except (OSError, sqlite3.Error) as error:
        raise StorageError(f"could not open snapshot storage at {path}: {error}") from error
    return connection
