"""Reads and writes filed-ticket records.

Filing the same finding twice against the same tracker would just spam
whatever is on the other end of it. This table is what `kubesentinel
ticket` checks before filing anything, keyed on a finding's own
deterministic id plus which ticketer it went to, since the same finding
could reasonably end up filed against more than one tracker.
"""

import sqlite3
from datetime import datetime

from kubesentinel.storage.db import StorageError


def already_filed(connection: sqlite3.Connection, finding_id: str, ticketer: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM filed_tickets WHERE finding_id = ? AND ticketer = ?",
        (finding_id, ticketer),
    ).fetchone()
    return row is not None


def record(
    connection: sqlite3.Connection,
    finding_id: str,
    ticketer: str,
    key: str,
    url: str | None,
    filed_at: datetime,
) -> None:
    try:
        connection.execute(
            """
            INSERT INTO filed_tickets (finding_id, ticketer, ticket_key, url, filed_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (finding_id, ticketer) DO UPDATE SET
                ticket_key = excluded.ticket_key,
                url = excluded.url,
                filed_at = excluded.filed_at
            """,
            (finding_id, ticketer, key, url, filed_at.isoformat()),
        )
        connection.commit()
    except sqlite3.Error as error:
        raise StorageError(f"could not record filed ticket for {finding_id}: {error}") from error
