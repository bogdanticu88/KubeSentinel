"""Files a KubeSentinel finding as a ServiceNow incident.

Built against the Table API, POST /api/now/table/incident, the same
approach ServiceNow's own integration docs point external callers at
rather than anything workflow-specific to one instance's configuration.

Not verified against a live instance, no credentials were available to
test against one. Tests cover the request shape and response handling
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

# ServiceNow urgency and impact both run 1 (highest) through 3 (lowest).
_URGENCY_BY_RISK = {"critical": "1", "high": "1", "medium": "2", "low": "3"}
_IMPACT_BY_RISK = {"critical": "1", "high": "2", "medium": "2", "low": "3"}


class ServiceNowTicketer:
    name = "servicenow"

    def __init__(
        self,
        instance: str | None = None,
        username: str | None = None,
        password: str | None = None,
        table: str = "incident",
        timeout_seconds: int = 30,
    ) -> None:
        self.instance = instance or os.environ.get("KUBESENTINEL_SERVICENOW_INSTANCE")
        self.username = username or os.environ.get("KUBESENTINEL_SERVICENOW_USERNAME")
        self.password = password or os.environ.get("KUBESENTINEL_SERVICENOW_PASSWORD")
        self.table = table
        self.timeout_seconds = timeout_seconds

    def is_configured(self) -> bool:
        return bool(self.instance and self.username and self.password)

    def file_finding(
        self, finding: Finding, gitops_source: GitOpsSource | None = None
    ) -> TicketResult:
        if not self.is_configured():
            raise TicketError(
                "ServiceNow is not configured, set KUBESENTINEL_SERVICENOW_INSTANCE, "
                "KUBESENTINEL_SERVICENOW_USERNAME, and KUBESENTINEL_SERVICENOW_PASSWORD"
            )

        username, password = self.username, self.password
        # is_configured() already guarantees these, spelled out again so
        # the type checker knows it too.
        assert username and password

        payload = {
            "short_description": build_ticket_title(finding),
            "description": build_ticket_body(finding, gitops_source),
            "urgency": _URGENCY_BY_RISK.get(finding.risk, "3"),
            "impact": _IMPACT_BY_RISK.get(finding.risk, "3"),
        }
        url = f"https://{self.instance}.service-now.com/api/now/table/{self.table}"

        try:
            response = requests.post(
                url,
                json=payload,
                auth=(username, password),
                headers={"Accept": "application/json"},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as error:
            raise TicketError(f"could not reach ServiceNow at {url}: {error}") from error

        if response.status_code >= 400:
            raise TicketError(
                f"ServiceNow rejected the incident ({response.status_code}): "
                f"{describe_http_error(response)}"
            )

        try:
            body = response.json()
        except ValueError as error:
            raise TicketError("ServiceNow returned a response that was not valid JSON") from error

        result = body.get("result") or {}
        number, sys_id = result.get("number"), result.get("sys_id")
        if not number or not sys_id:
            raise TicketError("ServiceNow response did not include an incident number")

        record_url = f"https://{self.instance}.service-now.com/nav_to.do?uri={self.table}.do?sys_id={sys_id}"
        return TicketResult(ticketer=self.name, key=number, url=record_url)
