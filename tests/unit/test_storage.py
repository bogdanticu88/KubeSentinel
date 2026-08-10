from datetime import UTC, datetime

import pytest

from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.scan import DimensionScore, ResourceCounts, ScoreResult, Snapshot
from kubesentinel.storage import db, snapshots
from kubesentinel.storage.db import StorageError


def _snapshot(cluster: str = "test-cluster", is_baseline: bool = False, score: int | None = 80) -> Snapshot:
    return Snapshot(
        cluster=cluster,
        taken_at=datetime.now(UTC),
        is_baseline=is_baseline,
        kubernetes_version="v1.30",
        node_count=1,
        resources=[
            CollectedResource(
                kind="Pod", api_version="v1", name="app", namespace="default", data={"hostNetwork": True}, raw={}
            )
        ],
        findings=[],
        score=ScoreResult(overall=score, dimensions=[DimensionScore(name="workloads", score=score)]),
        counts=ResourceCounts(workloads=1),
    )


def test_save_and_get_round_trips_everything(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    snap = _snapshot()

    snapshot_id = snapshots.save(connection, snap)
    loaded = snapshots.get(connection, snapshot_id)

    assert loaded is not None
    assert loaded.id == snapshot_id
    assert loaded.cluster == snap.cluster
    assert loaded.kubernetes_version == "v1.30"
    assert loaded.resources[0].kind == "Pod"
    assert loaded.resources[0].data == {"hostNetwork": True}
    assert loaded.score.overall == 80


def test_get_returns_none_for_a_missing_id(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    assert snapshots.get(connection, 999) is None


def test_get_latest_returns_the_most_recently_taken_snapshot(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    older = snapshots.save(connection, _snapshot())
    newer_snapshot = _snapshot()
    newer_snapshot = newer_snapshot.model_copy(
        update={"taken_at": newer_snapshot.taken_at.replace(year=newer_snapshot.taken_at.year + 1)}
    )
    newer = snapshots.save(connection, newer_snapshot)

    latest = snapshots.get_latest(connection, "test-cluster")

    assert latest.id == newer
    assert latest.id != older


def test_set_baseline_clears_any_previous_baseline_for_that_cluster(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    first = snapshots.save(connection, _snapshot(is_baseline=True))
    second = snapshots.save(connection, _snapshot())

    snapshots.set_baseline(connection, second)

    assert snapshots.get(connection, first).is_baseline is False
    assert snapshots.get(connection, second).is_baseline is True
    baseline = snapshots.get_baseline(connection, "test-cluster")
    assert baseline.id == second


def test_set_baseline_only_affects_the_matching_cluster(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    other_cluster_baseline = snapshots.save(connection, _snapshot(cluster="other-cluster", is_baseline=True))
    this_cluster = snapshots.save(connection, _snapshot(cluster="test-cluster"))

    snapshots.set_baseline(connection, this_cluster)

    assert snapshots.get(connection, other_cluster_baseline).is_baseline is True
    assert snapshots.get_baseline(connection, "test-cluster").id == this_cluster


def test_set_baseline_raises_for_an_unknown_snapshot_id(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    with pytest.raises(StorageError, match="no snapshot"):
        snapshots.set_baseline(connection, 12345)


def test_get_baseline_returns_none_when_nothing_is_set(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    snapshots.save(connection, _snapshot())
    assert snapshots.get_baseline(connection, "test-cluster") is None


def test_get_nearest_before_finds_the_closest_snapshot_not_after_the_cutoff(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    early = _snapshot().model_copy(update={"taken_at": datetime(2026, 1, 1, tzinfo=UTC)})
    late = _snapshot().model_copy(update={"taken_at": datetime(2026, 6, 1, tzinfo=UTC)})
    early_id = snapshots.save(connection, early)
    snapshots.save(connection, late)

    reference = snapshots.get_nearest_before(connection, "test-cluster", datetime(2026, 3, 1, tzinfo=UTC))

    assert reference.id == early_id


def test_list_snapshots_orders_newest_first(tmp_path):
    connection = db.connect(tmp_path / "test.db")
    early = _snapshot().model_copy(update={"taken_at": datetime(2026, 1, 1, tzinfo=UTC)})
    late = _snapshot().model_copy(update={"taken_at": datetime(2026, 6, 1, tzinfo=UTC)})
    snapshots.save(connection, early)
    late_id = snapshots.save(connection, late)

    listed = snapshots.list_snapshots(connection, "test-cluster")

    assert listed[0].id == late_id


def test_connect_wraps_filesystem_failures(tmp_path):
    # Point the db path at a location that cannot possibly become a
    # directory, a file already sits there with that exact name.
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("occupied")

    with pytest.raises(StorageError):
        db.connect(blocked / "kubesentinel.db")
