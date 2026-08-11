"""Renders findings as a SARIF 2.1.0 log.

SARIF was built for static analysis of source files, a result normally
points at a file and a line. KubeSentinel's findings are about live
cluster state, there is no file to point at, so each result carries a
SARIF logicalLocation (the resource's own kind and name) instead of a
physicalLocation. Generic SARIF viewers and GitHub's Security tab alert
list still ingest these findings fine, they just will not get an inline
file annotation the way a result on an actual source file would.
"""

from kubesentinel.models.finding import Finding
from kubesentinel.models.rule import Severity

_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SARIF_LEVEL: dict[Severity, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# Not part of the base SARIF spec, GitHub's code scanning UI reads this to
# pick an alert severity badge, roughly a CVSS-shaped 0-10 score.
_SECURITY_SEVERITY: dict[Severity, str] = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.0",
}


def render_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    return {
        "$schema": _SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KubeSentinel",
                        "version": tool_version,
                        "informationUri": "https://github.com/kubesentinel/kubesentinel",
                        "rules": _rule_catalog(findings),
                    }
                },
                "results": [_result(finding) for finding in findings],
            }
        ],
    }


def _rule_catalog(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
            "properties": {
                "tags": [finding.category],
                "security-severity": _SECURITY_SEVERITY[finding.severity],
            },
        }
    return list(seen.values())


def _result(finding: Finding) -> dict:
    resource = f"{finding.namespace}/{finding.resource}" if finding.namespace else finding.resource
    logical_name = f"{finding.resource_kind}/{resource}"
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.risk],
        "message": {"text": f"{finding.description} ({logical_name})"},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": logical_name, "kind": "resource"}]}
        ],
        "partialFingerprints": {"kubesentinelFindingId": finding.id},
    }
