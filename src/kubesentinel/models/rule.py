from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low"]

# Which score dimension a rule's findings count against. Set explicitly per
# rule rather than inferred from category, so scoring stays honest about
# what it actually measured.
Dimension = Literal["workloads", "identity", "networking", "exposure", "configuration"]

ConditionOperator = Literal[
    "equals", "not_equals", "exists", "not_exists", "in", "not_in", "contains", "intersects"
]

DEFAULT_EXCLUDED_NAMESPACES = ["kube-system", "kube-public", "kube-node-lease"]


class RuleCondition(BaseModel):
    """A single check against a resource's normalized data.

    `field` is a dotted path such as "containers[].securityContext.privileged".
    A segment suffixed with [] iterates a list, and a path can chain more
    than one of these, "containers[].command[]" resolves to every argument
    of every container. When a path resolves to several values, `quantifier`
    decides whether the condition needs to hold for at least one of them or
    for all of them.
    """

    field: str
    operator: ConditionOperator
    value: Any = None
    quantifier: Literal["any", "all"] = "any"


class RuleSelector(BaseModel):
    kinds: list[str] = Field(default_factory=list)
    # A resource must carry every key/value pair here to match, same
    # equality-AND semantics as a Kubernetes matchLabels selector. Empty
    # means no label restriction, matching by kind alone.
    match_labels: dict[str, str] = Field(default_factory=dict)


class Rule(BaseModel):
    id: str
    name: str
    category: str
    dimension: Dimension
    severity: Severity
    type: Literal["resource_match", "namespace_missing_resource"] = "resource_match"
    enabled: bool = True
    description: str

    # resource_match rules
    selector: RuleSelector | None = None
    conditions: list[RuleCondition] = Field(default_factory=list)

    # namespace_missing_resource rules
    require_absent_kind: str | None = None
    exclude_namespaces: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDED_NAMESPACES))

    risk_rationale: str
    remediation: str
    references: list[str] = Field(default_factory=list)
