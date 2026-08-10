"""Collects security-relevant resources from a cluster.

Every call here is a read-only list operation. Secrets are never collected
at all in this first pass, not even metadata, since nothing in the current
rule set needs them yet. A missing RBAC permission on one resource kind is
recorded as a warning and the scan continues; KubeSentinel is meant to run
under a least-privilege service account that will often not have every list
permission a cluster-admin kubeconfig has, and one denied call should not
take the whole scan down with it.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kubernetes import client
from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import MaxRetryError

from kubesentinel.collector.normalize import normalize_resource
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.scan import CollectionWarning, ResourceCounts

_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


@dataclass
class CollectionResult:
    resources: list[CollectedResource] = field(default_factory=list)
    counts: ResourceCounts = field(default_factory=ResourceCounts)
    warnings: list[CollectionWarning] = field(default_factory=list)
    node_count: int = 0


def collect(api_client: client.ApiClient, namespace: str | None = None) -> CollectionResult:
    result = CollectionResult()

    core = client.CoreV1Api(api_client)
    apps = client.AppsV1Api(api_client)
    batch = client.BatchV1Api(api_client)
    rbac = client.RbacAuthorizationV1Api(api_client)
    net = client.NetworkingV1Api(api_client)

    namespaced_kinds: list[tuple[str, Callable[[], Any], Callable[[], Any]]] = [
        ("Pod", core.list_pod_for_all_namespaces, lambda: core.list_namespaced_pod(namespace)),
        ("Deployment", apps.list_deployment_for_all_namespaces,
         lambda: apps.list_namespaced_deployment(namespace)),
        ("StatefulSet", apps.list_stateful_set_for_all_namespaces,
         lambda: apps.list_namespaced_stateful_set(namespace)),
        ("DaemonSet", apps.list_daemon_set_for_all_namespaces,
         lambda: apps.list_namespaced_daemon_set(namespace)),
        ("Job", batch.list_job_for_all_namespaces, lambda: batch.list_namespaced_job(namespace)),
        ("CronJob", batch.list_cron_job_for_all_namespaces,
         lambda: batch.list_namespaced_cron_job(namespace)),
        ("Service", core.list_service_for_all_namespaces,
         lambda: core.list_namespaced_service(namespace)),
        ("Ingress", net.list_ingress_for_all_namespaces,
         lambda: net.list_namespaced_ingress(namespace)),
        ("NetworkPolicy", net.list_network_policy_for_all_namespaces,
         lambda: net.list_namespaced_network_policy(namespace)),
        ("ServiceAccount", core.list_service_account_for_all_namespaces,
         lambda: core.list_namespaced_service_account(namespace)),
        ("Role", rbac.list_role_for_all_namespaces, lambda: rbac.list_namespaced_role(namespace)),
        ("RoleBinding", rbac.list_role_binding_for_all_namespaces,
         lambda: rbac.list_namespaced_role_binding(namespace)),
    ]
    for kind, all_namespaces_call, single_namespace_call in namespaced_kinds:
        call = single_namespace_call if namespace else all_namespaces_call
        _collect_kind(result, api_client, kind, call)

    # Namespaces, ClusterRoles and ClusterRoleBindings are cluster scoped and
    # always collected in full, a --namespace filter only narrows namespaced
    # resources, it does not hide the cluster-wide RBAC that can still reach
    # into that namespace.
    cluster_scoped_kinds = [
        ("Namespace", core.list_namespace),
        ("ClusterRole", rbac.list_cluster_role),
        ("ClusterRoleBinding", rbac.list_cluster_role_binding),
    ]
    for kind, call in cluster_scoped_kinds:
        _collect_kind(result, api_client, kind, call)

    result.node_count = _count_nodes(result, core)
    result.counts = _count_resources(result.resources)
    return result


def _collect_kind(
    result: CollectionResult,
    api_client: client.ApiClient,
    kind: str,
    list_call: Callable[[], Any],
) -> None:
    try:
        response = list_call()
    except ApiException as error:
        if error.status == 403:
            message = f"permission denied listing {kind}, findings for this kind will be incomplete"
        else:
            message = f"failed to list {kind}: HTTP {error.status} {error.reason}"
        result.warnings.append(CollectionWarning(resource_kind=kind, message=message))
        return
    except (MaxRetryError, OSError) as error:
        result.warnings.append(
            CollectionWarning(
                resource_kind=kind,
                message=f"could not reach the API server to list {kind}: {error}",
            )
        )
        return

    for item in response.items:
        try:
            raw = api_client.sanitize_for_serialization(item)
            metadata = raw.get("metadata") or {}
            data = normalize_resource(kind, raw)
        except (KeyError, TypeError, AttributeError) as malformed_error:
            result.warnings.append(
                CollectionWarning(
                    resource_kind=kind,
                    message=f"skipped a malformed {kind} object: {malformed_error}",
                )
            )
            continue

        result.resources.append(
            CollectedResource(
                kind=kind,
                api_version=raw.get("apiVersion", ""),
                name=metadata.get("name", ""),
                namespace=metadata.get("namespace"),
                uid=metadata.get("uid"),
                labels=metadata.get("labels") or {},
                annotations=metadata.get("annotations") or {},
                data=data,
                raw=raw,
            )
        )


def _count_nodes(result: CollectionResult, core: client.CoreV1Api) -> int:
    try:
        return len(core.list_node().items)
    except ApiException as error:
        result.warnings.append(
            CollectionWarning(
                resource_kind="Node",
                message=f"failed to list nodes: HTTP {error.status} {error.reason}",
            )
        )
        return 0
    except (MaxRetryError, OSError) as error:
        result.warnings.append(
            CollectionWarning(
                resource_kind="Node",
                message=f"could not reach the API server to count nodes: {error}",
            )
        )
        return 0


def _count_resources(resources: list[CollectedResource]) -> ResourceCounts:
    counts = ResourceCounts()
    for resource in resources:
        if resource.kind in _WORKLOAD_KINDS:
            counts.workloads += 1
        elif resource.kind == "Service":
            counts.services += 1
        elif resource.kind == "ServiceAccount":
            counts.service_accounts += 1
        elif resource.kind == "Role":
            counts.roles += 1
        elif resource.kind == "ClusterRole":
            counts.cluster_roles += 1
        elif resource.kind == "NetworkPolicy":
            counts.network_policies += 1
        elif resource.kind == "Namespace":
            counts.namespaces += 1
    return counts
