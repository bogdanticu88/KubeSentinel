from datetime import datetime

from pydantic import BaseModel, Field

from kubesentinel.models.finding import Finding
from kubesentinel.models.resource import CollectedResource


class ClusterInfo(BaseModel):
    name: str
    kubernetes_version: str | None = None
    node_count: int = 0


class ResourceCounts(BaseModel):
    workloads: int = 0
    services: int = 0
    service_accounts: int = 0
    roles: int = 0
    cluster_roles: int = 0
    network_policies: int = 0
    namespaces: int = 0


class DimensionScore(BaseModel):
    name: str
    score: int | None = None
    reasons: list[str] = Field(default_factory=list)


class ScoreResult(BaseModel):
    overall: int | None = None
    dimensions: list[DimensionScore] = Field(default_factory=list)


class CollectionWarning(BaseModel):
    resource_kind: str
    message: str


class ScanResult(BaseModel):
    cluster: ClusterInfo
    scanned_at: datetime
    counts: ResourceCounts
    findings: list[Finding] = Field(default_factory=list)
    score: ScoreResult
    warnings: list[CollectionWarning] = Field(default_factory=list)


class Snapshot(BaseModel):
    """A scan result persisted to local storage, resources included.

    ScanResult is what a single `scan` prints, a Snapshot is what `snapshot`
    keeps around afterward so drift and compare have something to diff
    against. It carries the raw resource list too, ScanResult does not,
    that is what a structural diff needs and findings alone cannot give it.
    """

    id: int | None = None
    cluster: str
    taken_at: datetime
    is_baseline: bool = False
    kubernetes_version: str | None = None
    node_count: int = 0
    resources: list[CollectedResource] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: ScoreResult
    counts: ResourceCounts
    warnings: list[CollectionWarning] = Field(default_factory=list)
