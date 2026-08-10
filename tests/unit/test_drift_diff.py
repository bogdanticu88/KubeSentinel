from datetime import UTC, datetime

from kubesentinel.engines.drift.diff import compare, diff_findings, diff_resources
from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.scan import DimensionScore, ResourceCounts, ScoreResult, Snapshot
from tests.fixtures import builders


def _finding(finding_id: str, resource: str = "app", namespace: str = "payments") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=finding_id,
        rule_id="KS-TEST-001",
        category="test",
        dimension="workloads",
        severity="high",
        risk="high",
        cluster="test",
        namespace=namespace,
        resource=resource,
        resource_kind="Deployment",
        title="test finding",
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind="Deployment", resource_name=resource, namespace=namespace),
        first_seen=now,
        last_seen=now,
    )


def test_diff_findings_reports_new_and_resolved_separately():
    baseline = [_finding("A"), _finding("B")]
    current = [_finding("A"), _finding("C")]

    new_findings, resolved_findings = diff_findings(baseline, current)

    assert [f.id for f in new_findings] == ["C"]
    assert [f.id for f in resolved_findings] == ["B"]


def test_diff_findings_with_identical_sets_reports_nothing():
    findings = [_finding("A"), _finding("B")]
    new_findings, resolved_findings = diff_findings(findings, list(findings))
    assert new_findings == []
    assert resolved_findings == []


def test_diff_resources_detects_added_and_removed():
    baseline = [builders.service(name="old-service")]
    current = [builders.service(name="new-service")]

    changes = diff_resources(baseline, current)

    change_types = {(c.name, c.change_type) for c in changes}
    assert ("new-service", "added") in change_types
    assert ("old-service", "removed") in change_types


def test_diff_resources_detects_a_changed_service_account():
    # Matches the project's own worked example: a workload's ServiceAccount
    # changing from a purpose-built one to default is a HIGH severity change,
    # not a cosmetic one.
    baseline = [builders.pod(name="payments-api", service_account_name="payments-api")]
    current = [builders.pod(name="payments-api", service_account_name="default")]

    changes = diff_resources(baseline, current)

    assert len(changes) == 1
    change = changes[0]
    assert change.change_type == "changed"
    field_change = next(fc for fc in change.field_changes if fc.field == "serviceAccountName")
    assert field_change.before == "payments-api"
    assert field_change.after == "default"
    assert field_change.severity == "high"


def test_diff_resources_a_container_becoming_privileged_is_critical():
    baseline = [builders.pod(containers=[{"name": "app", "securityContext": {"privileged": False}}])]
    current = [builders.pod(containers=[{"name": "app", "securityContext": {"privileged": True}}])]

    changes = diff_resources(baseline, current)

    field_change = next(fc for fc in changes[0].field_changes if fc.field == "containers")
    assert field_change.severity == "high"


def test_diff_resources_ignores_fields_that_did_not_change():
    resource = builders.pod(name="stable", host_network=False)
    changes = diff_resources([resource], [resource])
    assert changes == []


def test_diff_resources_field_not_in_the_severity_table_defaults_to_low():
    baseline = [
        CollectedResource(
            kind="Ingress", api_version="v1", name="app", namespace="default",
            data={"somethingUnlisted": "a"}, raw={},
        )
    ]
    current = [
        CollectedResource(
            kind="Ingress", api_version="v1", name="app", namespace="default",
            data={"somethingUnlisted": "b"}, raw={},
        )
    ]

    changes = diff_resources(baseline, current)

    field_change = next(fc for fc in changes[0].field_changes if fc.field == "somethingUnlisted")
    assert field_change.severity == "low"


def test_diff_resources_are_sorted_deterministically():
    baseline = []
    current = [
        builders.service(name="zzz"),
        builders.service(name="aaa"),
    ]
    changes = diff_resources(baseline, current)
    assert [c.name for c in changes] == ["aaa", "zzz"]


def _snapshot(score: int | None, findings: list[Finding]) -> Snapshot:
    return Snapshot(
        cluster="payments-cluster",
        taken_at=datetime.now(UTC),
        resources=[],
        findings=findings,
        score=ScoreResult(overall=score, dimensions=[DimensionScore(name="workloads", score=score)]),
        counts=ResourceCounts(),
    )


def test_compare_reports_the_score_delta_and_finding_movement():
    # Matches the project's own worked example: new findings, resolved
    # findings, and a score that moved between the two snapshots.
    baseline = _snapshot(score=88, findings=[_finding("resolved-1"), _finding("stays")])
    current = _snapshot(score=82, findings=[_finding("stays"), _finding("new-1")])

    report = compare(baseline, current)

    assert report.score_before == 88
    assert report.score_after == 82
    assert [f.id for f in report.new_findings] == ["new-1"]
    assert [f.id for f in report.resolved_findings] == ["resolved-1"]
