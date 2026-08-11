"""Shared ticket-filing interface and ticket text formatting.

Every ticketer answers the same two questions, is it configured and can it
file a finding, through this Protocol. `kubesentinel ticket` picks one by
name and does not care past that which system is actually on the other
end. Title and body formatting live here too rather than once per
ticketer, four systems each rendering the same finding slightly
differently would just make a future formatting bug harder to track down
to whether it was shared or system-specific.
"""

from typing import Protocol

import requests
from pydantic import BaseModel

from kubesentinel.gitops import GitOpsSource
from kubesentinel.models.finding import Finding


class TicketError(Exception):
    """Filing a ticket against an external tracker failed."""


class TicketResult(BaseModel):
    ticketer: str
    key: str
    url: str | None = None


class Ticketer(Protocol):
    name: str

    def is_configured(self) -> bool: ...

    def file_finding(
        self, finding: Finding, gitops_source: GitOpsSource | None = None
    ) -> TicketResult: ...


def build_ticket_title(finding: Finding) -> str:
    location = f"{finding.namespace}/{finding.resource}" if finding.namespace else finding.resource
    return f"[KubeSentinel] {finding.risk.upper()}: {finding.title} ({location})"


def build_ticket_body(finding: Finding, gitops_source: GitOpsSource | None) -> str:
    resource_line = f"Resource: {finding.resource_kind}/{finding.resource}"
    if finding.namespace:
        resource_line += f" in namespace {finding.namespace}"

    lines = [
        finding.description,
        "",
        f"Cluster: {finding.cluster}",
        resource_line,
        f"Severity: {finding.severity}, adjusted risk: {finding.risk}",
    ]
    if finding.risk_reasons:
        lines.append("Risk factors: " + ", ".join(finding.risk_reasons))

    lines += ["", "Remediation:", finding.remediation]

    if gitops_source is not None:
        lines += ["", _gitops_note(gitops_source)]

    if finding.references:
        lines += ["", "References:"]
        lines += [f"- {reference}" for reference in finding.references]

    lines += ["", f"KubeSentinel finding id: {finding.id}"]
    return "\n".join(lines)


def _gitops_note(source: GitOpsSource) -> str:
    if source.tool == "argocd":
        managed_by = f"ArgoCD application {source.name}"
    else:
        managed_by = f"Flux Kustomization {source.name}"
    if source.namespace:
        managed_by += f" (namespace {source.namespace})"
    return (
        f"This resource is managed by {managed_by}. Fix it in the source repository, "
        "a change applied directly to the cluster will drift and get reverted on the next sync."
    )


def describe_http_error(response: requests.Response) -> str:
    """A short, loggable summary of a failed HTTP response body."""
    try:
        body = response.json()
    except ValueError:
        return (response.text or f"HTTP {response.status_code}")[:300]
    return str(body)[:300]
