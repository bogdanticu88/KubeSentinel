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
