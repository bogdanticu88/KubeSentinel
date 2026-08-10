from typing import Any

from pydantic import BaseModel, Field


class CollectedResource(BaseModel):
    """A single Kubernetes object as observed during a scan.

    `data` holds the normalized view that rules are evaluated against. For
    workload kinds this is the pod spec pulled out from wherever it lives,
    a Pod has it directly, a Deployment or StatefulSet nests it under
    `spec.template.spec`, a CronJob nests it one level deeper still. Rules
    never need to know which kind they matched to find `containers` or
    `hostNetwork`. For everything else `data` is close to the object's raw
    `spec`. `raw` keeps the full object as returned by the API so a finding
    can quote the exact source field if needed later.
    """

    kind: str
    api_version: str
    name: str
    namespace: str | None = None
    uid: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
