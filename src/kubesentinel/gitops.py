"""Detects whether a collected resource is managed by ArgoCD or Flux.

Both tools stamp every resource they own with their own tracking label so
their own pruning and drift detection can find it again later. KubeSentinel
already collects every resource's labels for the rule engine, this just
reads the same data a second way: not "is this resource misconfigured" but
"who owns fixing it, and where". A finding on a GitOps-managed resource
should point at the source repository, not at a kubectl edit that will
just get reverted on the next sync.
"""

from typing import Literal

from pydantic import BaseModel

from kubesentinel.collector.normalize import WORKLOAD_KINDS
from kubesentinel.models.resource import CollectedResource

GitOpsTool = Literal["argocd", "flux"]

_ARGOCD_INSTANCE_LABEL = "argocd.argoproj.io/instance"
_FLUX_KUSTOMIZATION_NAME_LABEL = "kustomize.toolkit.fluxcd.io/name"
_FLUX_KUSTOMIZATION_NAMESPACE_LABEL = "kustomize.toolkit.fluxcd.io/namespace"
_FLUX_HELMRELEASE_NAME_LABEL = "helm.toolkit.fluxcd.io/name"
_FLUX_HELMRELEASE_NAMESPACE_LABEL = "helm.toolkit.fluxcd.io/namespace"


class GitOpsSource(BaseModel):
    tool: GitOpsTool
    name: str
    namespace: str | None = None


class GitOpsStatus(BaseModel):
    kind: str
    name: str
    namespace: str | None = None
    source: GitOpsSource | None = None


def detect_source(resource: CollectedResource) -> GitOpsSource | None:
    labels = resource.labels

    argocd_app = labels.get(_ARGOCD_INSTANCE_LABEL)
    if argocd_app:
        return GitOpsSource(tool="argocd", name=argocd_app)

    kustomization = labels.get(_FLUX_KUSTOMIZATION_NAME_LABEL)
    if kustomization:
        return GitOpsSource(
            tool="flux",
            name=kustomization,
            namespace=labels.get(_FLUX_KUSTOMIZATION_NAMESPACE_LABEL),
        )

    # helm-controller only stamps these when the HelmRelease has pruning or
    # drift detection turned on, a resource from a HelmRelease with neither
    # enabled will still come back as unmanaged here. Best effort, not a
    # guarantee, same as everything else this reads off labels alone.
    helm_release = labels.get(_FLUX_HELMRELEASE_NAME_LABEL)
    if helm_release:
        return GitOpsSource(
            tool="flux", name=helm_release, namespace=labels.get(_FLUX_HELMRELEASE_NAMESPACE_LABEL)
        )

    return None


def find_source(
    resource_kind: str,
    resource_name: str,
    namespace: str | None,
    resources: list[CollectedResource],
) -> GitOpsSource | None:
    for resource in resources:
        if (
            resource.kind == resource_kind
            and resource.name == resource_name
            and resource.namespace == namespace
        ):
            return detect_source(resource)
    return None


def detect_all(resources: list[CollectedResource]) -> list[GitOpsStatus]:
    return [
        GitOpsStatus(
            kind=resource.kind,
            name=resource.name,
            namespace=resource.namespace,
            source=detect_source(resource),
        )
        for resource in resources
        if resource.kind in WORKLOAD_KINDS
    ]
