"""Dotted-path field resolution and condition evaluation against resource data.

This is the part of the rule engine that lets a rule be written as data
instead of Python: "containers[].securityContext.privileged equals true"
rather than a hand-written function walking a container list. Keeping this
small and explicit is what lets rules stay contributable without needing to
touch engine code.
"""

from typing import Any

from kubesentinel.models.rule import RuleCondition


def resolve(data: dict[str, Any], field_path: str) -> list[Any]:
    """Resolve a dotted path against a dict.

    A path segment suffixed with [] iterates a list, contributing one
    resolved value per element rather than the list itself. Only one such
    segment is supported per path, that is enough for every rule shipped
    today. A path through a missing key resolves to no values at all, which
    condition evaluation treats as "the field is absent" rather than an
    error, since most of these fields are optional in the Kubernetes API.
    """
    values: list[Any] = [data]

    for segment in field_path.split("."):
        is_array = segment.endswith("[]")
        key = segment[:-2] if is_array else segment

        next_values: list[Any] = []
        for value in values:
            if not isinstance(value, dict):
                continue
            child = value.get(key)
            if child is None:
                continue
            if is_array:
                if isinstance(child, list):
                    next_values.extend(child)
            else:
                next_values.append(child)
        values = next_values
        if not values:
            break

    return values


def evaluate_condition(data: dict[str, Any], condition: RuleCondition) -> bool:
    values = resolve(data, condition.field)
    operator = condition.operator

    if operator == "exists":
        return len(values) > 0
    if operator == "not_exists":
        return len(values) == 0

    if not values:
        # The field is absent. That only satisfies checks looking for
        # absence or inequality, "not set" is not the same as "set to
        # something that differs from the expected value" for equals/in.
        return operator in ("not_equals", "not_in")

    checks = [_check_value(value, operator, condition.value) for value in values]
    return all(checks) if condition.quantifier == "all" else any(checks)


def _check_value(value: Any, operator: str, expected: Any) -> bool:
    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected
    if operator == "in":
        return value in expected
    if operator == "not_in":
        return value not in expected
    if operator == "contains":
        return isinstance(value, (list, str)) and expected in value
    if operator == "intersects":
        return isinstance(value, list) and bool(set(value) & set(expected))
    raise ValueError(f"unknown condition operator: {operator!r}")
