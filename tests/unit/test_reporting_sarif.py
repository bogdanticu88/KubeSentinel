from datetime import UTC, datetime

from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.reporting.sarif import render_sarif


def _finding(rule_id: str, severity: str, risk: str | None = None) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=f"KS-test-{rule_id}",
        rule_id=rule_id,
        category="workloads",
        dimension="workloads",
        severity=severity,
        risk=risk if risk is not None else severity,
        cluster="test",
        namespace="payments",
        resource="payments-api",
        resource_kind="Deployment",
        title="Privileged container",
        description="A container runs privileged.",
        risk_rationale="test",
        remediation="Set privileged: false.",
        evidence=Evidence(resource_kind="Deployment", resource_name="payments-api", namespace="payments"),
        first_seen=now,
        last_seen=now,
    )


def test_produces_one_run_with_a_result_per_finding():
    findings = [_finding("KS-WORKLOAD-001", "critical"), _finding("KS-WORKLOAD-002", "high")]
    sarif = render_sarif(findings)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_rule_catalog_is_deduplicated_by_rule_id():
    findings = [_finding("KS-WORKLOAD-001", "critical"), _finding("KS-WORKLOAD-001", "critical")]
    sarif = render_sarif(findings)

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "KS-WORKLOAD-001"


def test_severity_maps_to_sarif_level():
    critical = render_sarif([_finding("A", "critical")])["runs"][0]["results"][0]
    medium = render_sarif([_finding("B", "medium")])["runs"][0]["results"][0]
    low = render_sarif([_finding("C", "low")])["runs"][0]["results"][0]

    assert critical["level"] == "error"
    assert medium["level"] == "warning"
    assert low["level"] == "note"


def test_result_level_follows_risk_not_raw_severity():
    # A critical severity finding that correlation downgraded to a low risk
    # should read as a SARIF note, not an error, the result reflects
    # context, not the untouched rating.
    downgraded = _finding("A", severity="critical", risk="low")
    result = render_sarif([downgraded])["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_result_uses_a_logical_location_not_a_file():
    finding = _finding("KS-WORKLOAD-001", "critical")
    result = render_sarif([finding])["runs"][0]["results"][0]

    location = result["locations"][0]
    assert "logicalLocations" in location
    assert "physicalLocation" not in location
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "Deployment/payments/payments-api"


def test_finding_id_is_carried_as_a_partial_fingerprint():
    finding = _finding("KS-WORKLOAD-001", "critical")
    result = render_sarif([finding])["runs"][0]["results"][0]
    assert result["partialFingerprints"]["kubesentinelFindingId"] == finding.id


def test_empty_findings_still_produces_a_valid_empty_run():
    sarif = render_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
