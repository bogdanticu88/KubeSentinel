"""Builds the attack-path graph from collected resources.

Nodes are real Kubernetes objects (Service, Ingress, Workload,
ServiceAccount, Role or ClusterRole) plus three synthetic ones: Internet,
the entry point every path starts from, a per-namespace secrets-access node
(KubeSentinel never collects actual Secret objects or values, this
represents the capability to read them, not one specific secret), and a
single cluster-admin-equivalent sink for RBAC escalation. Edges are real,
verified relationships already sitting in the collected data: a Service's
type or an Ingress backend, a selector matching a workload's pod-template
labels, a workload's serviceAccountName, a Binding's subjects and roleRef,
an RBAC rule granting secrets or escalation verbs. Nothing here guesses,
every edge traces back to a specific field somewhere.
"""

import networkx as nx

from kubesentinel.collector.normalize import WORKLOAD_KINDS
from kubesentinel.models.resource import CollectedResource
from kubesentinel.relationships import (
    binding_targets_service_account,
    grants_escalation,
    grants_full_access,
    grants_secret_read,
    ingress_backend_service_names,
    pod_template_labels,
    role_rules,
)

INTERNET = "internet"
CLUSTER_ADMIN = "cluster-admin"
NODE_BREAKOUT = "node-breakout"

# Capabilities that, combined with a hostPath mount, are enough to reach
# outside the container onto the node itself.
_BREAKOUT_CAPABILITIES = {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_BOOT", "SYS_RAWIO", "ALL"}


def workload_node(resource: CollectedResource) -> str:
    return f"workload:{resource.namespace}:{resource.name}"


def service_node(resource: CollectedResource) -> str:
    return f"service:{resource.namespace}:{resource.name}"


def ingress_node(resource: CollectedResource) -> str:
    return f"ingress:{resource.namespace}:{resource.name}"


def service_account_node(namespace: str | None, name: str) -> str:
    return f"serviceaccount:{namespace}:{name}"


def role_node(namespace: str | None, kind: str, name: str) -> str:
    return f"role:{namespace}:{kind}:{name}"


def secrets_node(namespace: str | None) -> str:
    return f"secrets:{namespace}"


def build_graph(resources: list[CollectedResource]) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(INTERNET, kind="Internet", identifier="Internet")
    graph.add_node(CLUSTER_ADMIN, kind="ClusterAdmin", identifier="cluster-admin equivalent access")
    graph.add_node(NODE_BREAKOUT, kind="Node", identifier="node compromise")

    _add_exposure_edges(graph, resources)
    _add_workload_edges(graph, resources)
    _add_service_account_edges(graph, resources)
    _add_role_edges(graph, resources)
    _add_breakout_edges(graph, resources)
    return graph


def _add_exposure_edges(graph: nx.DiGraph, resources: list[CollectedResource]) -> None:
    services_by_key = {(r.namespace, r.name): r for r in resources if r.kind == "Service"}

    for resource in resources:
        if resource.kind != "Service":
            continue
        node_id = service_node(resource)
        graph.add_node(node_id, kind="Service", identifier=f"{resource.namespace}/{resource.name}")
        if resource.data.get("type") in ("LoadBalancer", "NodePort"):
            graph.add_edge(INTERNET, node_id, relation="exposed_via", confidence="reachable")

    for resource in resources:
        if resource.kind != "Ingress":
            continue
        node_id = ingress_node(resource)
        graph.add_node(node_id, kind="Ingress", identifier=f"{resource.namespace}/{resource.name}")
        graph.add_edge(INTERNET, node_id, relation="routes_through", confidence="reachable")

        for service_name in ingress_backend_service_names(resource.data):
            backend = services_by_key.get((resource.namespace, service_name))
            if backend is None:
                continue
            graph.add_edge(
                node_id, service_node(backend), relation="routes_to", confidence="reachable"
            )


def _add_workload_edges(graph: nx.DiGraph, resources: list[CollectedResource]) -> None:
    services = [r for r in resources if r.kind == "Service"]

    for workload in resources:
        if workload.kind not in WORKLOAD_KINDS:
            continue
        labels = pod_template_labels(workload)
        node_id = workload_node(workload)
        added = False

        for service in services:
            selector = service.data.get("selector") or {}
            if not selector or service.namespace != workload.namespace:
                continue
            if not selector.items() <= labels.items():
                continue
            if not added:
                graph.add_node(
                    node_id, kind=workload.kind, identifier=f"{workload.namespace}/{workload.name}"
                )
                added = True
            graph.add_edge(
                service_node(service), node_id, relation="routes_to", confidence="reachable"
            )


def _add_service_account_edges(graph: nx.DiGraph, resources: list[CollectedResource]) -> None:
    for workload in resources:
        if workload.kind not in WORKLOAD_KINDS:
            continue
        node_id = workload_node(workload)
        if node_id not in graph:
            continue
        sa_name = workload.data.get("serviceAccountName") or "default"
        sa_node_id = service_account_node(workload.namespace, sa_name)
        sa_identifier = f"{workload.namespace}/{sa_name}"
        graph.add_node(sa_node_id, kind="ServiceAccount", identifier=sa_identifier)
        graph.add_edge(node_id, sa_node_id, relation="runs_as", confidence="reachable")


def _add_role_edges(graph: nx.DiGraph, resources: list[CollectedResource]) -> None:
    rules = role_rules(resources)
    bindings = [r for r in resources if r.kind in ("RoleBinding", "ClusterRoleBinding")]

    sa_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "ServiceAccount"]
    for sa_node_id in sa_nodes:
        _, sa_namespace, sa_name = sa_node_id.split(":", 2)

        for binding in bindings:
            if not binding_targets_service_account(binding, sa_namespace, sa_name):
                continue
            role_ref = binding.data.get("roleRef") or {}
            role_kind, role_name = role_ref.get("kind"), role_ref.get("name")
            if not role_kind or not role_name:
                continue
            role_identity_namespace = binding.namespace if role_kind == "Role" else None
            role_key = (role_identity_namespace, role_kind, role_name)
            rule_list = rules.get(role_key)
            if rule_list is None:
                continue

            role_node_id = role_node(role_identity_namespace, role_kind, role_name)
            role_label = f"{role_identity_namespace or 'cluster'}/{role_name}"
            graph.add_node(role_node_id, kind=role_kind, identifier=role_label)
            graph.add_edge(sa_node_id, role_node_id, relation="bound_to", confidence="reachable")

            # A RoleBinding, even one referencing a ClusterRole, only grants
            # access within its own namespace, only a ClusterRoleBinding
            # actually reaches every namespace.
            grant_namespace = binding.namespace if binding.kind == "RoleBinding" else None
            _add_capability_edges(graph, role_node_id, rule_list, grant_namespace)


def _add_capability_edges(
    graph: nx.DiGraph, role_node_id: str, rules: list[dict], grant_namespace: str | None
) -> None:
    if any(grants_secret_read(rule) for rule in rules):
        target = secrets_node(grant_namespace)
        label = "all namespaces" if grant_namespace is None else grant_namespace
        graph.add_node(target, kind="Secrets", identifier=f"secrets in {label}")
        graph.add_edge(role_node_id, target, relation="can_read", confidence="reachable")

    # Computed as aggregates before adding any edge, a role usually has more
    # than one rule, and the strongest grant across all of them decides the
    # edge, not whichever rule a loop happens to process last.
    if any(grants_full_access(rule) for rule in rules):
        graph.add_edge(
            role_node_id, CLUSTER_ADMIN, relation="has_full_access", confidence="reachable"
        )
    elif any(grants_escalation(rule) for rule in rules):
        graph.add_edge(role_node_id, CLUSTER_ADMIN, relation="can_escalate", confidence="possible")


def _add_breakout_edges(graph: nx.DiGraph, resources: list[CollectedResource]) -> None:
    for workload in resources:
        if workload.kind not in WORKLOAD_KINDS:
            continue
        node_id = workload_node(workload)
        if node_id not in graph:
            continue
        if _can_break_out_to_node(workload):
            graph.add_edge(node_id, NODE_BREAKOUT, relation="host_mount", confidence="theoretical")


def _can_break_out_to_node(workload: CollectedResource) -> bool:
    volumes = workload.data.get("volumes") or []
    has_hostpath = any("hostPath" in (volume or {}) for volume in volumes)
    if not has_hostpath:
        return False
    for container in workload.data.get("containers") or []:
        security_context = container.get("securityContext") or {}
        if security_context.get("privileged"):
            return True
        added_capabilities = (security_context.get("capabilities") or {}).get("add") or []
        if set(added_capabilities) & _BREAKOUT_CAPABILITIES:
            return True
    return False
