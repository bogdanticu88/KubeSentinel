"""Normalization of raw Kubernetes API objects into the shape rules evaluate.

Rules are written once against a normalized field layout instead of once per
resource kind. A privileged-container check should not care whether it is
looking at a bare Pod or a Deployment's pod template, so this module is what
absorbs that difference before a rule ever runs.
"""

from typing import Any

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}

_POD_SPEC_FIELDS = (
    "containers",
    "initContainers",
    "hostNetwork",
    "hostPID",
    "hostIPC",
    "serviceAccountName",
    "automountServiceAccountToken",
    "volumes",
    "securityContext",
)


def _extract_pod_spec(pod_spec: dict[str, Any]) -> dict[str, Any]:
    return {field: pod_spec[field] for field in _POD_SPEC_FIELDS if field in pod_spec}


def _workload_pod_spec(kind: str, spec: dict[str, Any]) -> dict[str, Any]:
    if kind == "Pod":
        return _extract_pod_spec(spec)

    if kind == "CronJob":
        job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        pod_template = job_spec.get("template") or {}
        return _extract_pod_spec(pod_template.get("spec") or {})

    pod_template = spec.get("template") or {}
    return _extract_pod_spec(pod_template.get("spec") or {})


def normalize_resource(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Return the normalized view a rule condition is evaluated against.

    `raw` is the full sanitized object as returned by the API (metadata,
    spec, status and all), not just its spec, since a few kinds (Role,
    RoleBinding) keep the fields rules care about at the top level rather
    than nested under `spec`.
    """
    if kind in WORKLOAD_KINDS:
        return _workload_pod_spec(kind, raw.get("spec") or {})

    if kind in ("Role", "ClusterRole"):
        return {"rules": raw.get("rules") or []}

    if kind in ("RoleBinding", "ClusterRoleBinding"):
        return {"subjects": raw.get("subjects") or [], "roleRef": raw.get("roleRef") or {}}

    if kind == "ServiceAccount":
        return {"automountServiceAccountToken": raw.get("automountServiceAccountToken")}

    # Service, Ingress, NetworkPolicy and anything else not special-cased
    # above is already flat enough at .spec for rules to read directly.
    return raw.get("spec") or {}
