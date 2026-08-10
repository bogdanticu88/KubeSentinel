"""Reads and writes Snapshot rows.

Every function here takes an already-open connection, callers own the
connection's lifetime, this module just knows how a Snapshot maps to a row
and back.
"""

import sqlite3
from datetime import datetime

from pydantic import TypeAdapter

from kubesentinel.models.finding import Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.scan import CollectionWarning, ResourceCounts, ScoreResult, Snapshot
from kubesentinel.storage.db import StorageError

_RESOURCES_ADAPTER = TypeAdapter(list[CollectedResource])
_FINDINGS_ADAPTER = TypeAdapter(list[Finding])
_WARNINGS_ADAPTER = TypeAdapter(list[CollectionWarning])


def save(connection: sqlite3.Connection, snapshot: Snapshot) -> int:
    try:
        cursor = connection.execute(
            """
            INSERT INTO snapshots (
                cluster, taken_at, is_baseline, kubernetes_version, node_count,
                score_overall, resources_json, findings_json, score_json,
                counts_json, warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.cluster,
                snapshot.taken_at.isoformat(),
                int(snapshot.is_baseline),
                snapshot.kubernetes_version,
                snapshot.node_count,
                snapshot.score.overall,
                _RESOURCES_ADAPTER.dump_json(snapshot.resources).decode(),
                _FINDINGS_ADAPTER.dump_json(snapshot.findings).decode(),
                snapshot.score.model_dump_json(),
                snapshot.counts.model_dump_json(),
                _WARNINGS_ADAPTER.dump_json(snapshot.warnings).decode(),
            ),
        )
        connection.commit()
    except sqlite3.Error as error:
        raise StorageError(f"could not save snapshot: {error}") from error
    if cursor.lastrowid is None:
        raise StorageError("saved a snapshot but sqlite did not return its row id")
    return cursor.lastrowid


def get(connection: sqlite3.Connection, snapshot_id: int) -> Snapshot | None:
    row = connection.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    return _row_to_snapshot(row) if row else None


def get_baseline(connection: sqlite3.Connection, cluster: str) -> Snapshot | None:
    row = connection.execute(
        """
        SELECT * FROM snapshots
        WHERE cluster = ? AND is_baseline = 1
        ORDER BY taken_at DESC LIMIT 1
        """,
        (cluster,),
    ).fetchone()
    return _row_to_snapshot(row) if row else None


def get_latest(connection: sqlite3.Connection, cluster: str) -> Snapshot | None:
    row = connection.execute(
        "SELECT * FROM snapshots WHERE cluster = ? ORDER BY taken_at DESC LIMIT 1",
        (cluster,),
    ).fetchone()
    return _row_to_snapshot(row) if row else None


def get_nearest_before(
    connection: sqlite3.Connection, cluster: str, before: datetime
) -> Snapshot | None:
    row = connection.execute(
        """
        SELECT * FROM snapshots
        WHERE cluster = ? AND taken_at <= ?
        ORDER BY taken_at DESC LIMIT 1
        """,
        (cluster, before.isoformat()),
    ).fetchone()
    return _row_to_snapshot(row) if row else None


def list_snapshots(connection: sqlite3.Connection, cluster: str) -> list[Snapshot]:
    rows = connection.execute(
        "SELECT * FROM snapshots WHERE cluster = ? ORDER BY taken_at DESC", (cluster,)
    ).fetchall()
    return [_row_to_snapshot(row) for row in rows]


def set_baseline(connection: sqlite3.Connection, snapshot_id: int) -> None:
    row = connection.execute(
        "SELECT cluster FROM snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    if row is None:
        raise StorageError(f"no snapshot with id {snapshot_id}")
    try:
        connection.execute(
            "UPDATE snapshots SET is_baseline = 0 WHERE cluster = ?", (row["cluster"],)
        )
        connection.execute("UPDATE snapshots SET is_baseline = 1 WHERE id = ?", (snapshot_id,))
        connection.commit()
    except sqlite3.Error as error:
        raise StorageError(f"could not set snapshot {snapshot_id} as baseline: {error}") from error


def _row_to_snapshot(row: sqlite3.Row) -> Snapshot:
    return Snapshot(
        id=row["id"],
        cluster=row["cluster"],
        taken_at=datetime.fromisoformat(row["taken_at"]),
        is_baseline=bool(row["is_baseline"]),
        kubernetes_version=row["kubernetes_version"],
        node_count=row["node_count"],
        resources=_RESOURCES_ADAPTER.validate_json(row["resources_json"]),
        findings=_FINDINGS_ADAPTER.validate_json(row["findings_json"]),
        score=ScoreResult.model_validate_json(row["score_json"]),
        counts=ResourceCounts.model_validate_json(row["counts_json"]),
        warnings=_WARNINGS_ADAPTER.validate_json(row["warnings_json"]),
    )
