"""Files a KubeSentinel finding as a Jira issue.

Built against Jira's REST API v2, POST /rest/api/2/issue with a plain
string description, still supported on Cloud, Server, and Data Center
alike. v3 replaced the plain description with Atlassian Document Format,
which would need a small ADF renderer just to say the same thing v2 says
in one string, not worth it for this.

Not verified against a live Jira instance, no credentials were available
to test against one. Tests cover the request shape and response handling
against the documented API only, see docs/roadmap.md.
"""

import os
from typing import Any

import requests

from kubesentinel.gitops import GitOpsSource
from kubesentinel.integrations.ticketer import (
    TicketError,
    TicketResult,
    build_ticket_body,
    build_ticket_title,
    describe_http_error,
)
from kubesentinel.models.finding import Finding

_ISSUE_TYPE_BY_RISK = {
    "critical": "Bug",
    "high": "Bug",
    "medium": "Task",
    "low": "Task",
}


class JiraTicketer:
    name = "jira"

    def __init__(
        self,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        self.base_url = base_url or os.environ.get("KUBESENTINEL_JIRA_URL")
        self.email = email or os.environ.get("KUBESENTINEL_JIRA_EMAIL")
        self.api_token = api_token or os.environ.get("KUBESENTINEL_JIRA_API_TOKEN")
        self.project_key = project_key or os.environ.get("KUBESENTINEL_JIRA_PROJECT")
        self.timeout_seconds = timeout_seconds

    def is_configured(self) -> bool:
        return bool(self.base_url and self.email and self.api_token and self.project_key)

    def file_finding(
        self, finding: Finding, gitops_source: GitOpsSource | None = None
    ) -> TicketResult:
        if not self.is_configured():
            raise TicketError(
                "Jira is not configured, set KUBESENTINEL_JIRA_URL, KUBESENTINEL_JIRA_EMAIL, "
                "KUBESENTINEL_JIRA_API_TOKEN, and KUBESENTINEL_JIRA_PROJECT"
            )

        base_url, email, api_token = self.base_url, self.email, self.api_token
        # is_configured() already guarantees these three, spelled out again
        # so the type checker knows it too rather than treating every field
        # as possibly None all the way down.
        assert base_url and email and api_token

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": build_ticket_title(finding),
                "description": build_ticket_body(finding, gitops_source),
                "issuetype": {"name": _ISSUE_TYPE_BY_RISK.get(finding.risk, "Task")},
                "labels": ["kubesentinel", f"risk-{finding.risk}"],
            }
        }
        url = f"{base_url.rstrip('/')}/rest/api/2/issue"

        try:
            response = requests.post(
                url, json=payload, auth=(email, api_token), timeout=self.timeout_seconds
            )
        except requests.RequestException as error:
            raise TicketError(f"could not reach Jira at {self.base_url}: {error}") from error

        if response.status_code >= 400:
            raise TicketError(
                f"Jira rejected the issue ({response.status_code}): {describe_http_error(response)}"
            )

        try:
            body = response.json()
        except ValueError as error:
            raise TicketError("Jira returned a response that was not valid JSON") from error

        key = body.get("key")
        if not key:
            raise TicketError("Jira response did not include an issue key")
        browse_url = f"{base_url.rstrip('/')}/browse/{key}"
        return TicketResult(ticketer=self.name, key=key, url=browse_url)
