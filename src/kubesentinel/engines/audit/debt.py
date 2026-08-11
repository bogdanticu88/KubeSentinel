"""Tracks security debt: findings that persist across scans rather than
getting fixed.

A finding's id is deterministic, the same misconfiguration on the same
resource gets the same id every scan, so its age and recurrence can be
read straight off how many stored snapshots it has shown up in. No
separate tracking table needed, the snapshot history already has the
answer.
"""

from datetime import datetime

from kubesentinel.models.finding import Finding
from kubesentinel.models.scan import Snapshot
from kubesentinel.models.securitydebt import (
    DebtTrend,
    SecurityDebtCategory,
    SecurityDebtItem,
    SecurityDebtReport,
)


def compute_security_debt(snapshots: list[Snapshot]) -> SecurityDebtReport:
    """`snapshots` must be ordered oldest to newest, the last one is "now"."""
    if not snapshots:
        return SecurityDebtReport(total_open=0)

    first_seen, recurrence, latest_by_id = _history(snapshots)
    current = snapshots[-1]
    items = _open_items(current, first_seen, recurrence, latest_by_id)
    by_category = _group_by_category(items)
    previous_total, trend = _trend(snapshots, len(items))

    return SecurityDebtReport(
        total_open=len(items),
        by_category=by_category,
        items=items,
        trend=trend,
        previous_total=previous_total,
    )


def _history(
    snapshots: list[Snapshot],
) -> tuple[dict[str, datetime], dict[str, int], dict[str, Finding]]:
    first_seen: dict[str, datetime] = {}
    recurrence: dict[str, int] = {}
    latest_by_id: dict[str, Finding] = {}

    for snapshot in snapshots:
        for finding in snapshot.findings:
            if finding.id not in first_seen:
                first_seen[finding.id] = snapshot.taken_at
            recurrence[finding.id] = recurrence.get(finding.id, 0) + 1
            latest_by_id[finding.id] = finding

    return first_seen, recurrence, latest_by_id


def _open_items(
    current: Snapshot,
    first_seen: dict[str, datetime],
    recurrence: dict[str, int],
    latest_by_id: dict[str, Finding],
) -> list[SecurityDebtItem]:
    items = []
    for finding in current.findings:
        age_days = (current.taken_at - first_seen[finding.id]).days
        items.append(
            SecurityDebtItem(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                category=finding.category,
                resource_kind=finding.resource_kind,
                resource=finding.resource,
                namespace=finding.namespace,
                risk=finding.risk,
                age_days=age_days,
                recurrence=recurrence[finding.id],
            )
        )
    items.sort(key=lambda item: item.age_days, reverse=True)
    return items


def _group_by_category(items: list[SecurityDebtItem]) -> list[SecurityDebtCategory]:
    by_category: dict[str, list[SecurityDebtItem]] = {}
    for item in items:
        by_category.setdefault(item.category, []).append(item)

    categories = [
        SecurityDebtCategory(
            category=category,
            count=len(category_items),
            oldest_age_days=max(item.age_days for item in category_items),
        )
        for category, category_items in by_category.items()
    ]
    categories.sort(key=lambda c: c.count, reverse=True)
    return categories


def _trend(snapshots: list[Snapshot], current_total: int) -> tuple[int | None, DebtTrend]:
    if len(snapshots) < 2:
        return None, "unknown"

    previous_total = len(snapshots[-2].findings)
    if current_total > previous_total:
        return previous_total, "increasing"
    if current_total < previous_total:
        return previous_total, "decreasing"
    return previous_total, "unchanged"
