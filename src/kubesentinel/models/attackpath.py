from typing import Literal

from pydantic import BaseModel, Field

from kubesentinel.models.rule import Severity

# Ordered weakest to strongest, a path's confidence is capped by whatever
# its weakest edge can honestly claim. "reachable" means every edge is a
# verified structural relationship, an attacker just has to compromise the
# entry workload and walk it. "possible" means at least one edge needs the
# attacker to actively use a granted capability (escalate, bind,
# impersonate) rather than just follow a wire that already exists.
# "theoretical" means we cannot confirm the mechanism actually works
# (a hostPath mount might not point at anything exploitable).
# "high_confidence" is reserved for a path whose entry workload already has
# a real open finding, a vulnerability or misconfiguration gives an
# attacker an actual way in, not just a hypothetical one.
Confidence = Literal["theoretical", "possible", "reachable", "high_confidence"]


class PathNode(BaseModel):
    kind: str
    identifier: str


class AttackPath(BaseModel):
    # Assigned after every path in a scan is found and risk-sorted, "AP-1"
    # is the highest risk path in that scan, not a stable identifier across
    # scans the way a Finding's id is.
    id: str = ""
    entry_point: str = "Internet"
    target_kind: str
    target: str
    nodes: list[PathNode] = Field(default_factory=list)
    confidence: Confidence
    risk: Severity
    summary: str
