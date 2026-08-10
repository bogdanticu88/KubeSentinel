from datetime import UTC, datetime

from kubesentinel.engines.risk.scoring import score
from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.models.rule import Rule


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


def _rule(dimension: str) -> Rule:
    return Rule(
        id=f"KS-TEST-{dimension}",
        name="test rule",
        category="test",
        dimension=dimension,
        severity="low",
        description="test",
        selector={"kinds": ["Pod"]},
        conditions=[{"field": "x", "operator": "exists"}],
        risk_rationale="test",
        remediation="test",
    )


COVERED_DIMENSIONS = ["identity", "workloads", "networking", "exposure"]
RULES = [_rule(dimension) for dimension in COVERED_DIMENSIONS]


def test_no_findings_gives_perfect_score_on_covered_dimensions():
    result = score([], RULES)
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.score == 100
    assert workloads.reasons == []


def test_uncovered_dimension_reports_none_not_a_fake_score():
    result = score([], RULES)
    configuration = next(d for d in result.dimensions if d.name == "configuration")
    assert configuration.score is None
    assert configuration.reasons


def test_a_dimension_scores_even_with_zero_findings_once_a_rule_covers_it():
    result = score([], [_rule("configuration")])
    configuration = next(d for d in result.dimensions if d.name == "configuration")
    # A clean cluster with real configuration rules loaded should score 100,
    # not report "not available", coverage is decided by the rule set, not
    # by whether this particular scan happened to find something.
    assert configuration.score == 100


def test_penalty_scales_with_severity():
    critical_only = score([_finding("workloads", "critical")], RULES)
    low_only = score([_finding("workloads", "low")], RULES)
    critical_score = next(d for d in critical_only.dimensions if d.name == "workloads").score
    low_score = next(d for d in low_only.dimensions if d.name == "workloads").score
    assert critical_score < low_score


def test_score_floors_at_zero_rather_than_going_negative():
    findings = [_finding("workloads", "critical") for _ in range(10)]
    result = score(findings, RULES)
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.score == 0


def test_overall_is_average_of_computed_dimensions_only():
    result = score([_finding("workloads", "critical")], RULES)
    computed = [d.score for d in result.dimensions if d.score is not None]
    assert result.overall == round(sum(computed) / len(computed))


def test_reasons_are_sorted_most_severe_first():
    findings = [_finding("workloads", "low"), _finding("workloads", "critical")]
    result = score(findings, RULES)
    workloads = next(d for d in result.dimensions if d.name == "workloads")
    assert workloads.reasons[0].startswith("CRITICAL")
    assert workloads.reasons[1].startswith("LOW")


def test_a_finding_on_a_covered_dimension_is_scored():
    result = score([_finding("configuration", "high")], [_rule("configuration")])
    configuration = next(d for d in result.dimensions if d.name == "configuration")
    assert configuration.score == 100 - 12
