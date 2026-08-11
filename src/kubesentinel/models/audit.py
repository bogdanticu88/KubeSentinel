from datetime import datetime

from pydantic import BaseModel, Field

from kubesentinel.models.drift import DriftReport
from kubesentinel.models.securitydebt import SecurityDebtReport


class AuditReport(BaseModel):
    number: int
    cluster: str
    taken_at: datetime
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    score: int | None = None
    # None only for a cluster's very first audit, with neither a previous
    # audit nor a baseline to compare against yet.
    drift: DriftReport | None = None
    new_attack_paths: int = 0
    previous_attack_paths: int = 0
    security_debt: SecurityDebtReport
