from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from kubesentinel.models.rule import Severity


class Evidence(BaseModel):
    resource_kind: str
    resource_name: str
    namespace: str | None = None
    matched_fields: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    rule_id: str
    category: str
    dimension: str
    severity: Severity
    status: Literal["open"] = "open"

    cluster: str
    namespace: str | None = None
    resource: str
    resource_kind: str

    title: str
    description: str
    risk_rationale: str
    remediation: str
    references: list[str] = Field(default_factory=list)

    evidence: Evidence
    first_seen: datetime
    last_seen: datetime

    # `severity` is the intrinsic rating (a rule's own severity, or a CVE's
    # vendor rating) and never changes. `risk` starts equal to severity and
    # is what the correlation engine adjusts once it knows whether this
    # finding's workload is internet-exposed or sits behind privileged RBAC,
    # the same CVE can be a HIGH in one cluster and a CRITICAL in another.
    risk: Severity
    risk_reasons: list[str] = Field(default_factory=list)

    # Set only on vulnerability findings produced by a scanner adapter, None
    # for every misconfiguration finding.
    cve: str | None = None
    image: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
