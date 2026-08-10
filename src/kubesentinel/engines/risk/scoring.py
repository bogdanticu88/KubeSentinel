"""Deterministic, explainable security scoring.

Each dimension starts at 100 and loses points for every open finding in
that dimension, weighted by the finding's risk, not its raw severity. Risk
is what the correlation engine produces once it knows a finding's exposure
and RBAC context, severity alone would score a critical CVE on an isolated
internal workload the same as one sitting behind a wildcard ServiceAccount
on an internet-facing Service, which is exactly the gap this project exists
to close. Findings that correlation never touches (RBAC and networking
findings on the Role/Service itself, not a workload) keep risk equal to
severity, so this still behaves like severity-weighted scoring for them.

A dimension with no rule assigned to it at all reports score=None instead
of a fake 100, since "no rules cover this yet" is not the same claim as
"nothing is wrong". That has to be judged by whether any *rule* targets the
dimension, not by whether this particular scan happened to find something,
a clean cluster with real configuration rules loaded should score 100 on
Configuration, not "not available". Supply Chain is a special case of the
same principle: nothing in the rule set targets it, its findings come from
a scanner adapter instead, so coverage there has to be told explicitly that
a scan actually ran, a clean image with zero CVEs still needs to score 100.
"""

from kubesentinel.models.finding import Finding
from kubesentinel.models.rule import Dimension, Rule
from kubesentinel.models.scan import DimensionScore, ScoreResult

RISK_PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2}

ALL_DIMENSIONS: list[Dimension] = [
    "identity",
    "workloads",
    "networking",
    "exposure",
    "configuration",
    "supply_chain",
]


def score(
    findings: list[Finding],
    rules: list[Rule],
    extra_covered_dimensions: set[str] | None = None,
) -> ScoreResult:
    covered_dimensions = {rule.dimension for rule in rules} | (extra_covered_dimensions or set())

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
    penalty = sum(RISK_PENALTY[finding.risk] for finding in findings)
    dimension_score = max(0, 100 - penalty)

    ranked = sorted(findings, key=lambda f: RISK_PENALTY[f.risk], reverse=True)
    reasons = [f"{f.risk.upper()}: {f.title} on {f.resource_kind}/{f.resource}" for f in ranked]

    return dimension_score, reasons
