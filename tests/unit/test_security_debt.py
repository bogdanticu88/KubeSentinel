from datetime import UTC, datetime, timedelta

from kubesentinel.engines.audit.debt import compute_security_debt
from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.models.scan import ResourceCounts, ScoreResult, Snapshot


def _finding(finding_id: str, category: str = "workloads", risk: str = "high") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=finding_id,
        rule_id=f"KS-{finding_id}",
        category=category,
        dimension="workloads",
        severity=risk,
        risk=risk,
        cluster="test",
        namespace="default",
        resource="app",
        resource_kind="Deployment",
        title=f"finding {finding_id}",
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind="Deployment", resource_name="app"),
        first_seen=now,
        last_seen=now,
    )


def _snapshot(taken_at: datetime, findings: list[Finding]) -> Snapshot:
    return Snapshot(
        cluster="test",
        taken_at=taken_at,
        resources=[],
        findings=findings,
        score=ScoreResult(overall=80),
        counts=ResourceCounts(),
    )


def test_no_snapshots_reports_zero_debt():
    report = compute_security_debt([])
    assert report.total_open == 0
    assert report.trend == "unknown"


def test_a_single_snapshot_has_no_trend_yet():
    now = datetime.now(UTC)
    report = compute_security_debt([_snapshot(now, [_finding("A")])])
    assert report.total_open == 1
    assert report.trend == "unknown"
    assert report.previous_total is None


def test_a_finding_present_since_the_first_snapshot_ages_correctly():
    day_one = datetime.now(UTC) - timedelta(days=10)
    day_ten = datetime.now(UTC)
    finding = _finding("A")

    snapshots = [_snapshot(day_one, [finding]), _snapshot(day_ten, [finding])]
    report = compute_security_debt(snapshots)

    assert report.items[0].finding_id == "A"
    assert report.items[0].age_days == 10
    assert report.items[0].recurrence == 2


def test_a_finding_only_seen_in_the_latest_snapshot_has_zero_age():
    day_one = datetime.now(UTC) - timedelta(days=10)
    now = datetime.now(UTC)
    old_finding = _finding("A")
    new_finding = _finding("B")

    snapshots = [_snapshot(day_one, [old_finding]), _snapshot(now, [old_finding, new_finding])]
    report = compute_security_debt(snapshots)

    new_item = next(i for i in report.items if i.finding_id == "B")
    assert new_item.age_days == 0
    assert new_item.recurrence == 1


def test_a_resolved_finding_does_not_appear_in_current_debt():
    day_one = datetime.now(UTC) - timedelta(days=5)
    now = datetime.now(UTC)
    resolved = _finding("A")
    still_open = _finding("B")

    snapshots = [_snapshot(day_one, [resolved, still_open]), _snapshot(now, [still_open])]
    report = compute_security_debt(snapshots)

    assert {i.finding_id for i in report.items} == {"B"}
    assert report.total_open == 1


def test_trend_increasing_when_more_findings_now_than_last_snapshot():
    earlier = datetime.now(UTC) - timedelta(days=1)
    now = datetime.now(UTC)
    snapshots = [
        _snapshot(earlier, [_finding("A")]),
        _snapshot(now, [_finding("A"), _finding("B")]),
    ]
    report = compute_security_debt(snapshots)
    assert report.trend == "increasing"
    assert report.previous_total == 1


def test_trend_decreasing_when_fewer_findings_now_than_last_snapshot():
    earlier = datetime.now(UTC) - timedelta(days=1)
    now = datetime.now(UTC)
    snapshots = [
        _snapshot(earlier, [_finding("A"), _finding("B")]),
        _snapshot(now, [_finding("A")]),
    ]
    report = compute_security_debt(snapshots)
    assert report.trend == "decreasing"


def test_items_grouped_and_counted_by_category():
    now = datetime.now(UTC)
    findings = [
        _finding("A", category="networking"),
        _finding("B", category="networking"),
        _finding("C", category="rbac"),
    ]
    report = compute_security_debt([_snapshot(now, findings)])

    by_category = {c.category: c.count for c in report.by_category}
    assert by_category == {"networking": 2, "rbac": 1}


def test_items_sorted_oldest_first():
    day_ten = datetime.now(UTC) - timedelta(days=10)
    day_one = datetime.now(UTC) - timedelta(days=1)
    now = datetime.now(UTC)
    old_finding = _finding("OLD")
    new_finding = _finding("NEW")

    snapshots = [
        _snapshot(day_ten, [old_finding]),
        _snapshot(day_one, [old_finding, new_finding]),
        _snapshot(now, [old_finding, new_finding]),
    ]
    report = compute_security_debt(snapshots)

    assert report.items[0].finding_id == "OLD"
    assert report.items[0].age_days > report.items[1].age_days
