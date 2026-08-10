from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from kubesentinel.models.finding import Finding
from kubesentinel.models.rule import Severity


class FieldChange(BaseModel):
    field: str
    before: Any = None
    after: Any = None
    severity: Severity


class ResourceChange(BaseModel):
    kind: str
    namespace: str | None
    name: str
    change_type: Literal["added", "removed", "changed"]
    field_changes: list[FieldChange] = Field(default_factory=list)


class DriftReport(BaseModel):
    baseline_cluster: str
    baseline_taken_at: datetime
    current_taken_at: datetime
    score_before: int | None
    score_after: int | None
    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    resource_changes: list[ResourceChange] = Field(default_factory=list)
