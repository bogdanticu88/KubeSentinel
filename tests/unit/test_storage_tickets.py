from datetime import UTC, datetime

import pytest

from kubesentinel.storage import db, tickets
from kubesentinel.storage.db import StorageError


def test_a_finding_not_yet_filed_is_not_already_filed(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    assert tickets.already_filed(connection, "KS-1", "github") is False


def test_recording_a_ticket_makes_it_show_up_as_already_filed(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    tickets.record(connection, "KS-1", "github", "42", "https://github.com/acme/repo/issues/42", datetime.now(UTC))

    assert tickets.already_filed(connection, "KS-1", "github") is True


def test_the_same_finding_can_be_filed_against_two_different_ticketers(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    tickets.record(connection, "KS-1", "github", "42", None, datetime.now(UTC))

    assert tickets.already_filed(connection, "KS-1", "jira") is False
    tickets.record(connection, "KS-1", "jira", "SEC-9", None, datetime.now(UTC))
    assert tickets.already_filed(connection, "KS-1", "jira") is True


def test_recording_the_same_finding_and_ticketer_twice_updates_rather_than_duplicates(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    tickets.record(connection, "KS-1", "github", "42", "https://old", datetime.now(UTC))
    tickets.record(connection, "KS-1", "github", "42", "https://new", datetime.now(UTC))

    rows = connection.execute(
        "SELECT url FROM filed_tickets WHERE finding_id = ? AND ticketer = ?", ("KS-1", "github")
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["url"] == "https://new"


def test_a_read_against_a_broken_database_raises_storage_error(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    connection.execute("DROP TABLE filed_tickets")

    with pytest.raises(StorageError, match="could not check"):
        tickets.already_filed(connection, "KS-1", "github")
