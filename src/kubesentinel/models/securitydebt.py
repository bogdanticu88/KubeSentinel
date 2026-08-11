from typing import Literal

from pydantic import BaseModel, Field

from kubesentinel.models.rule import Severity

DebtTrend = Literal["increasing", "decreasing", "unchanged", "unknown"]


class SecurityDebtItem(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    category: str
    resource_kind: str
    resource: str
    namespace: str | None
    risk: Severity
    age_days: int
    recurrence: int


class SecurityDebtCategory(BaseModel):
    category: str
    count: int
    oldest_age_days: int


class SecurityDebtReport(BaseModel):
    total_open: int
    by_category: list[SecurityDebtCategory] = Field(default_factory=list)
    items: list[SecurityDebtItem] = Field(default_factory=list)
    trend: DebtTrend = "unknown"
    previous_total: int | None = None
