from datetime import UTC, datetime

from kubesentinel.gitops import GitOpsSource
from kubesentinel.integrations.ticketer import (
    build_ticket_body,
    build_ticket_title,
    describe_http_error,
)
from kubesentinel.models.finding import Evidence, Finding


def _finding(
    risk: str = "high",
    namespace: str | None = "payments",
    risk_reasons: list[str] | None = None,
    references: list[str] | None = None,
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="KS-test-001",
        rule_id="KS-WORKLOAD-001",
        category="workloads",
        dimension="workloads",
        severity="critical",
        risk=risk,
        risk_reasons=risk_reasons or [],
        cluster="kind-test",
        namespace=namespace,
        resource="payments-api",
        resource_kind="Deployment",
        title="Privileged container",
        description="A container runs privileged.",
        risk_rationale="test",
        remediation="Set privileged: false.",
        references=references or [],
        evidence=Evidence(resource_kind="Deployment", resource_name="payments-api", namespace=namespace),
        first_seen=now,
        last_seen=now,
    )


def test_title_includes_risk_and_namespaced_location():
    title = build_ticket_title(_finding(risk="critical", namespace="payments"))
    assert title == "[KubeSentinel] CRITICAL: Privileged container (payments/payments-api)"


def test_title_drops_the_namespace_segment_for_a_cluster_scoped_finding():
    title = build_ticket_title(_finding(risk="high", namespace=None))
    assert title == "[KubeSentinel] HIGH: Privileged container (payments-api)"


def test_body_includes_description_resource_and_remediation():
    body = build_ticket_body(_finding(), gitops_source=None)
    assert "A container runs privileged." in body
    assert "Deployment/payments-api in namespace payments" in body
    assert "Set privileged: false." in body
    assert "KubeSentinel finding id: KS-test-001" in body


def test_body_includes_risk_factors_when_present():
    finding = _finding(risk_reasons=["internet-exposed", "wildcard RBAC"])
    body = build_ticket_body(finding, gitops_source=None)
    assert "Risk factors: internet-exposed, wildcard RBAC" in body


def test_body_omits_risk_factors_line_when_there_are_none():
    body = build_ticket_body(_finding(risk_reasons=[]), gitops_source=None)
    assert "Risk factors" not in body


def test_body_lists_references_when_present():
    finding = _finding(references=["https://example.com/CVE-2026-1"])
    body = build_ticket_body(finding, gitops_source=None)
    assert "- https://example.com/CVE-2026-1" in body


def test_body_notes_an_argocd_managed_resource():
    source = GitOpsSource(tool="argocd", name="payments-app")
    body = build_ticket_body(_finding(), gitops_source=source)
    assert "managed by ArgoCD application payments-app" in body
    assert "drift and get reverted" in body


def test_body_notes_a_flux_managed_resource_with_its_namespace():
    source = GitOpsSource(tool="flux", name="payments-kustomization", namespace="flux-system")
    body = build_ticket_body(_finding(), gitops_source=source)
    assert "managed by Flux Kustomization payments-kustomization" in body
    assert "(namespace flux-system)" in body


def test_body_has_no_gitops_note_when_the_resource_is_unmanaged():
    body = build_ticket_body(_finding(), gitops_source=None)
    assert "managed by" not in body


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json body")
        return self._payload


def test_describe_http_error_prefers_the_json_body():
    response = _FakeResponse(400, payload={"errorMessages": ["project key is required"]})
    assert "project key is required" in describe_http_error(response)


def test_describe_http_error_falls_back_to_raw_text():
    response = _FakeResponse(500, payload=None, text="internal server error")
    assert describe_http_error(response) == "internal server error"


def test_describe_http_error_falls_back_to_status_code_when_body_is_empty():
    response = _FakeResponse(503, payload=None, text="")
    assert describe_http_error(response) == "HTTP 503"
