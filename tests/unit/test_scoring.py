from datetime import UTC, datetime

from kubesentinel.engines.risk.scoring import score
from kubesentinel.models.finding import Evidence, Finding


def _finding(dimension: str, severity: str) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=f"KS-{dimension}-{severity}",
        rule_id="KS-TEST-001",
        category="test",
        dimension=dimension,
        severity=severity,
        cluster="test",
        namespace="default",
        resource="app",
        resource_kind="Pod",
        title="test finding",
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind="Pod", resource_name="app"),
        first_seen=now,
        last_seen=now,
    )


def test_no_findings_gives_perfect_score_on_covered_dimensions():
    result = score([])
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.score == 100
    assert workloads.reasons == []


def test_uncovered_dimension_reports_none_not_a_fake_score():
    result = score([])
    configuration = next(d for d in result.dimensions if d.name == "configuration")
    assert configuration.score is None
    assert configuration.reasons


def test_penalty_scales_with_severity():
    critical_only = score([_finding("workloads", "critical")])
    low_only = score([_finding("workloads", "low")])
    critical_score = next(d for d in critical_only.dimensions if d.name == "workloads").score
    low_score = next(d for d in low_only.dimensions if d.name == "workloads").score
    assert critical_score < low_score


def test_score_floors_at_zero_rather_than_going_negative():
    findings = [_finding("workloads", "critical") for _ in range(10)]
    result = score(findings)
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.score == 0


def test_overall_is_average_of_computed_dimensions_only():
    result = score([_finding("workloads", "critical")])
    computed = [d.score for d in result.dimensions if d.score is not None]
    assert result.overall == round(sum(computed) / len(computed))


def test_reasons_are_sorted_most_severe_first():
    findings = [_finding("workloads", "low"), _finding("workloads", "critical")]
    result = score(findings)
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.reasons[0].startswith("CRITICAL")
    assert workloads.reasons[1].startswith("LOW")


def test_a_dimension_with_a_real_finding_is_scored_even_if_marked_not_yet_covered():
    result = score([_finding("configuration", "high")])
    configuration = next(d for d in result.dimensions if d.name == "configuration")
    assert configuration.score == 100 - 12
