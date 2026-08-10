"""Deterministic, explainable security scoring.

Each dimension starts at 100 and loses points for every open finding in
that dimension, weighted by severity. This is a straightforward
severity-weighted score, not a true attacker cost/benefit model yet. A real
cost/benefit weighting needs exposure and reachability context from the
attack path engine, which does not exist as of this milestone, so this
scoring is a reasonable first approximation rather than the final model.

A dimension with no rule assigned to it at all reports score=None instead
of a fake 100, since "no rules cover this yet" is not the same claim as
"nothing is wrong". That has to be judged by whether any *rule* targets the
dimension, not by whether this particular scan happened to find something,
a clean cluster with real configuration rules loaded should score 100 on
Configuration, not "not available".
"""

from kubesentinel.models.finding import Finding
from kubesentinel.models.rule import Dimension, Rule
from kubesentinel.models.scan import DimensionScore, ScoreResult

SEVERITY_PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2}

ALL_DIMENSIONS: list[Dimension] = [
    "identity",
    "workloads",
    "networking",
    "exposure",
    "configuration",
]


def score(findings: list[Finding], rules: list[Rule]) -> ScoreResult:
    covered_dimensions = {rule.dimension for rule in rules}

    by_dimension: dict[str, list[Finding]] = {dimension: [] for dimension in ALL_DIMENSIONS}
    for finding in findings:
        by_dimension.setdefault(finding.dimension, []).append(finding)

    dimensions: list[DimensionScore] = []
    computed: list[int] = []

    for dimension in ALL_DIMENSIONS:
        if dimension not in covered_dimensions:
            dimensions.append(
                DimensionScore(
                    name=dimension,
                    score=None,
                    reasons=[f"no rule is assigned to the {dimension} dimension yet"],
                )
            )
            continue

        dimension_score, reasons = _score_dimension(by_dimension[dimension])
        dimensions.append(DimensionScore(name=dimension, score=dimension_score, reasons=reasons))
        computed.append(dimension_score)

    overall = round(sum(computed) / len(computed)) if computed else None
    return ScoreResult(overall=overall, dimensions=dimensions)


def _score_dimension(findings: list[Finding]) -> tuple[int, list[str]]:
    penalty = sum(SEVERITY_PENALTY[finding.severity] for finding in findings)
    dimension_score = max(0, 100 - penalty)

    ranked = sorted(findings, key=lambda f: SEVERITY_PENALTY[f.severity], reverse=True)
    reasons = [f"{f.severity.upper()}: {f.title} on {f.resource_kind}/{f.resource}" for f in ranked]

    return dimension_score, reasons
