from datetime import UTC, datetime

from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.models.scan import (
    ClusterInfo,
    CollectionWarning,
    DimensionScore,
    ResourceCounts,
    ScanResult,
    ScoreResult,
)
from kubesentinel.reporting.html import render_html


def _finding(title: str = "Privileged container", risk: str = "critical") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="KS-test",
        rule_id="KS-WORKLOAD-001",
        category="workloads",
        dimension="workloads",
        severity=risk,
        risk=risk,
        cluster="test",
        namespace="payments",
        resource="payments-api",
        resource_kind="Deployment",
        title=title,
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind="Deployment", resource_name="payments-api", namespace="payments"),
        first_seen=now,
        last_seen=now,
    )


def _scan_result(findings: list[Finding], cluster_name: str = "test-cluster") -> ScanResult:
    return ScanResult(
        cluster=ClusterInfo(name=cluster_name, kubernetes_version="v1.30", node_count=1),
        scanned_at=datetime.now(UTC),
        counts=ResourceCounts(workloads=1),
        findings=findings,
        score=ScoreResult(
            overall=72, dimensions=[DimensionScore(name="workloads", score=72, reasons=["test"])]
        ),
    )


def test_renders_a_complete_html_document():
    html_doc = render_html(_scan_result([_finding()]))
    assert html_doc.startswith("<!doctype html>")
    assert "</html>" in html_doc
    assert "test-cluster" in html_doc


def test_score_is_shown():
    html_doc = render_html(_scan_result([]))
    assert "72/100" in html_doc


def test_missing_score_renders_as_not_available_not_a_python_none():
    result = _scan_result([])
    result = result.model_copy(update={"score": ScoreResult(overall=None, dimensions=[])})
    html_doc = render_html(result)
    assert "None/100" not in html_doc
    assert "n/a/100" in html_doc


def test_a_hostile_finding_title_is_escaped_not_injected():
    # CVE titles come from an external database, KubeSentinel does not
    # control their content, this has to be safe to open from disk.
    hostile = _finding(title="<script>alert(1)</script>")
    html_doc = render_html(_scan_result([hostile]))
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc


def test_a_hostile_cluster_name_is_escaped():
    html_doc = render_html(_scan_result([], cluster_name='"><img src=x onerror=alert(1)>'))
    assert "<img src=x" not in html_doc


def test_findings_are_sorted_by_risk_critical_first():
    low = _finding(title="low issue", risk="low")
    critical = _finding(title="critical issue", risk="critical")
    html_doc = render_html(_scan_result([low, critical]))
    assert html_doc.index("critical issue") < html_doc.index("low issue")


def test_warnings_section_only_appears_when_there_are_warnings():
    without_warnings = render_html(_scan_result([]))
    assert "Warnings" not in without_warnings

    result = _scan_result([])
    result = result.model_copy(
        update={"warnings": [CollectionWarning(resource_kind="Pod", message="permission denied")]}
    )
    with_warnings = render_html(result)
    assert "permission denied" in with_warnings
