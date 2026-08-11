"""Files a KubeSentinel finding as an Azure DevOps work item.

Built against the Work Items REST API, POST .../_apis/wit/workitems/$Bug
with a JSON Patch body, authenticated with a personal access token the
way Azure DevOps' own docs describe for a non-interactive caller.

Not verified against a live organization, no credentials were available
to test against one. Tests cover the request shape and response handling
against the documented API only, see docs/roadmap.md.
"""

import os

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

_SEVERITY_BY_RISK = {
    "critical": "1 - Critical",
    "high": "2 - High",
    "medium": "3 - Medium",
    "low": "4 - Low",
}


class AzureDevOpsTicketer:
    name = "azuredevops"

    def __init__(
        self,
        organization: str | None = None,
        project: str | None = None,
        personal_access_token: str | None = None,
        work_item_type: str = "Bug",
        api_version: str = "7.1",
        timeout_seconds: int = 30,
    ) -> None:
        self.organization = organization or os.environ.get("KUBESENTINEL_AZDO_ORG")
        self.project = project or os.environ.get("KUBESENTINEL_AZDO_PROJECT")
        self.personal_access_token = personal_access_token or os.environ.get(
            "KUBESENTINEL_AZDO_PAT"
        )
        self.work_item_type = work_item_type
        self.api_version = api_version
        self.timeout_seconds = timeout_seconds

    def is_configured(self) -> bool:
        return bool(self.organization and self.project and self.personal_access_token)

    def file_finding(
        self, finding: Finding, gitops_source: GitOpsSource | None = None
    ) -> TicketResult:
        if not self.is_configured():
            raise TicketError(
                "Azure DevOps is not configured, set KUBESENTINEL_AZDO_ORG, "
                "KUBESENTINEL_AZDO_PROJECT, and KUBESENTINEL_AZDO_PAT"
            )

        personal_access_token = self.personal_access_token
        # is_configured() already guarantees this, spelled out again so the
        # type checker knows it too.
        assert personal_access_token

        # Azure DevOps work item descriptions render as HTML, a bare
        # newline does nothing visually, it needs an actual line break.
        description = build_ticket_body(finding, gitops_source).replace("\n", "<br>")
        patch = [
            {"op": "add", "path": "/fields/System.Title", "value": build_ticket_title(finding)},
            {"op": "add", "path": "/fields/System.Description", "value": description},
            {
                "op": "add",
                "path": "/fields/Microsoft.VSTS.Common.Severity",
                "value": _SEVERITY_BY_RISK.get(finding.risk, "4 - Low"),
            },
        ]
        url = (
            f"https://dev.azure.com/{self.organization}/{self.project}/_apis/wit/workitems/"
            f"${self.work_item_type}?api-version={self.api_version}"
        )

        try:
            response = requests.post(
                url,
                json=patch,
                auth=("", personal_access_token),
                headers={"Content-Type": "application/json-patch+json"},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as error:
            raise TicketError(f"could not reach Azure DevOps at {url}: {error}") from error

        if response.status_code >= 400:
            raise TicketError(
                f"Azure DevOps rejected the work item ({response.status_code}): "
                f"{describe_http_error(response)}"
            )

        try:
            body = response.json()
        except ValueError as error:
            raise TicketError("Azure DevOps returned a response that was not valid JSON") from error

        work_item_id = body.get("id")
        if not work_item_id:
            raise TicketError("Azure DevOps response did not include a work item id")

        web_url = ((body.get("_links") or {}).get("html") or {}).get("href")
        return TicketResult(ticketer=self.name, key=str(work_item_id), url=web_url)
