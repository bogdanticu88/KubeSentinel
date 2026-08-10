"""Small factories for building CollectedResource objects in tests.

These mirror what the real collector produces: a raw dict shaped like the
sanitized (camelCase) API object, run through the same normalize_resource
function the collector uses, so a test exercises the real normalization
path instead of hand-crafting `data` directly.
"""

from typing import Any

from kubesentinel.collector.normalize import normalize_resource
from kubesentinel.models.resource import CollectedResource


def build_resource(
    kind: str,
    name: str,
    body: dict[str, Any],
    namespace: str | None = "default",
    labels: dict[str, str] | None = None,
) -> CollectedResource:
    raw: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace, "labels": labels or {}},
    }
    raw.update(body)
    data = normalize_resource(kind, raw)
    return CollectedResource(
        kind=kind,
        api_version=raw["apiVersion"],
        name=name,
        namespace=namespace,
        labels=labels or {},
        data=data,
        raw=raw,
    )


def pod(
    name: str = "test-pod",
    namespace: str = "default",
    containers: list[dict[str, Any]] | None = None,
    host_network: bool = False,
    host_pid: bool = False,
    host_ipc: bool = False,
    volumes: list[dict[str, Any]] | None = None,
    service_account_name: str | None = None,
) -> CollectedResource:
    spec: dict[str, Any] = {
        "containers": containers if containers is not None else [{"name": "app", "image": "app:1.0"}],
        "hostNetwork": host_network,
        "hostPID": host_pid,
        "hostIPC": host_ipc,
    }
    if volumes is not None:
        spec["volumes"] = volumes
    if service_account_name is not None:
        spec["serviceAccountName"] = service_account_name
    return build_resource("Pod", name, {"spec": spec}, namespace=namespace)


def deployment(
    name: str = "test-deployment",
    namespace: str = "default",
    containers: list[dict[str, Any]] | None = None,
) -> CollectedResource:
    pod_spec = {"containers": containers if containers is not None else [{"name": "app"}]}
    spec = {"template": {"spec": pod_spec}}
    return build_resource("Deployment", name, {"spec": spec}, namespace=namespace)


def cron_job(
    name: str = "test-cronjob",
    namespace: str = "default",
    containers: list[dict[str, Any]] | None = None,
) -> CollectedResource:
    pod_spec = {"containers": containers if containers is not None else [{"name": "app"}]}
    spec = {"jobTemplate": {"spec": {"template": {"spec": pod_spec}}}}
    return build_resource("CronJob", name, {"spec": spec}, namespace=namespace)


def role(
    name: str = "test-role",
    namespace: str = "default",
    rules: list[dict[str, Any]] | None = None,
    kind: str = "Role",
    labels: dict[str, str] | None = None,
) -> CollectedResource:
    body = {"rules": rules if rules is not None else []}
    return build_resource(kind, name, body, namespace=namespace, labels=labels)


def role_binding(
    name: str = "test-binding",
    namespace: str = "default",
    subjects: list[dict[str, Any]] | None = None,
    kind: str = "RoleBinding",
) -> CollectedResource:
    body = {
        "subjects": subjects if subjects is not None else [],
        "roleRef": {"kind": "Role", "name": "test-role"},
    }
    return build_resource(kind, name, body, namespace=namespace)


def service(
    name: str = "test-service",
    namespace: str = "default",
    service_type: str = "ClusterIP",
) -> CollectedResource:
    return build_resource("Service", name, {"spec": {"type": service_type}}, namespace=namespace)


def ingress(
    name: str = "test-ingress",
    namespace: str = "default",
    tls: list[dict[str, Any]] | None = None,
) -> CollectedResource:
    spec: dict[str, Any] = {}
    if tls is not None:
        spec["tls"] = tls
    return build_resource("Ingress", name, {"spec": spec}, namespace=namespace)


def network_policy(name: str = "test-netpol", namespace: str = "default") -> CollectedResource:
    return build_resource("NetworkPolicy", name, {"spec": {"podSelector": {}}}, namespace=namespace)


def namespace(name: str) -> CollectedResource:
    return CollectedResource(
        kind="Namespace",
        api_version="v1",
        name=name,
        namespace=None,
        data={},
        raw={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}},
    )
