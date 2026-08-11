import networkx as nx

from kubesentinel.engines.attackpath.graph import (
    CLUSTER_ADMIN,
    INTERNET,
    NODE_BREAKOUT,
    build_graph,
    role_node,
    secrets_node,
    service_account_node,
    service_node,
    workload_node,
)
from tests.fixtures import builders


def test_loadbalancer_service_connects_internet_to_a_matching_workload():
    pod = builders.pod(name="app", labels={"app": "web"})
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    assert graph.has_edge(INTERNET, service_node(service))
    assert graph.has_edge(service_node(service), workload_node(pod))


def test_clusterip_service_alone_is_not_reachable_from_internet():
    pod = builders.pod(name="app", labels={"app": "web"})
    service = builders.service(service_type="ClusterIP", selector={"app": "web"})

    graph = build_graph([pod, service])

    # the workload is still connected to the service, ClusterIP just never
    # gets an edge from Internet in the first place, so there is no path in
    assert not graph.has_edge(INTERNET, service_node(service))
    assert not nx.has_path(graph, INTERNET, workload_node(pod))


def test_ingress_backed_clusterip_service_is_reachable():
    pod = builders.pod(name="app", labels={"app": "web"})
    service = builders.service(name="web-svc", service_type="ClusterIP", selector={"app": "web"})
    ingress = builders.ingress(
        rules=[{"http": {"paths": [{"backend": {"service": {"name": "web-svc"}}}]}}]
    )

    graph = build_graph([pod, service, ingress])

    ingress_id = f"ingress:{ingress.namespace}:{ingress.name}"
    assert graph.has_edge(INTERNET, ingress_id)
    assert graph.has_edge(ingress_id, service_node(service))
    assert graph.has_edge(service_node(service), workload_node(pod))


def test_selector_must_match_namespace_too():
    pod = builders.pod(name="app", namespace="ns-a", labels={"app": "web"})
    service = builders.service(namespace="ns-b", service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    assert workload_node(pod) not in graph


def test_workload_connects_to_its_service_account():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    sa_id = service_account_node(pod.namespace, "app-sa")
    assert graph.has_edge(workload_node(pod), sa_id)


def test_default_service_account_used_when_none_set():
    pod = builders.pod(name="app", labels={"app": "web"})
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    sa_id = service_account_node(pod.namespace, "default")
    assert graph.has_edge(workload_node(pod), sa_id)


def test_wildcard_role_reaches_cluster_admin_with_reachable_confidence():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    role = builders.role(name="broad", rules=[{"resources": ["*"], "verbs": ["*"]}])
    binding = builders.role_binding(
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="Role",
        role_ref_name="broad",
    )

    graph = build_graph([pod, service, role, binding])

    role_id = role_node("default", "Role", "broad")
    edge = graph.edges[role_id, CLUSTER_ADMIN]
    assert edge["confidence"] == "reachable"


def test_read_only_wildcard_resources_does_not_reach_cluster_admin():
    # Confirmed against a real cluster: narrowing a wildcard-resources role
    # down to get/list should stop looking like a path to full cluster
    # compromise. Reading everything is still a real problem, the secrets
    # edge already covers that, but it cannot create, modify, or delete
    # anything, which is a meaningfully smaller risk than cluster-admin.
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    role = builders.role(name="read-only", rules=[{"resources": ["*"], "verbs": ["get", "list"]}])
    binding = builders.role_binding(
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="Role",
        role_ref_name="read-only",
    )

    graph = build_graph([pod, service, role, binding])

    role_id = role_node("default", "Role", "read-only")
    assert not graph.has_edge(role_id, CLUSTER_ADMIN)
    # still flagged for reading every secret in the namespace, that part is correct
    assert graph.has_edge(role_id, secrets_node("default"))


def test_wildcard_resources_with_a_write_verb_reaches_cluster_admin():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    role = builders.role(name="writer", rules=[{"resources": ["*"], "verbs": ["get", "delete"]}])
    binding = builders.role_binding(
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="Role",
        role_ref_name="writer",
    )

    graph = build_graph([pod, service, role, binding])

    role_id = role_node("default", "Role", "writer")
    edge = graph.edges[role_id, CLUSTER_ADMIN]
    assert edge["confidence"] == "reachable"


def test_escalation_verb_without_wildcard_reaches_cluster_admin_with_possible_confidence():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    role = builders.role(name="escalator", rules=[{"resources": ["roles"], "verbs": ["escalate"]}])
    binding = builders.role_binding(
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="Role",
        role_ref_name="escalator",
    )

    graph = build_graph([pod, service, role, binding])

    role_id = role_node("default", "Role", "escalator")
    edge = graph.edges[role_id, CLUSTER_ADMIN]
    assert edge["confidence"] == "possible"


def test_rolebinding_scopes_a_clusterrole_grant_to_its_own_namespace():
    pod = builders.pod(name="app", namespace="team-a", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(namespace="team-a", service_type="LoadBalancer", selector={"app": "web"})
    cluster_role = builders.role(
        name="secret-reader", kind="ClusterRole", rules=[{"resources": ["secrets"], "verbs": ["get"]}]
    )
    binding = builders.role_binding(
        namespace="team-a",
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "team-a"}],
        role_ref_kind="ClusterRole",
        role_ref_name="secret-reader",
    )

    graph = build_graph([pod, service, cluster_role, binding])

    # bound via a RoleBinding, so the grant node itself is scoped to team-a,
    # not the ClusterRole's own cluster-wide identity
    role_id = role_node("team-a", "ClusterRole", "secret-reader")
    assert graph.has_edge(role_id, secrets_node("team-a"))
    assert not graph.has_edge(role_id, secrets_node(None))


def test_clusterrolebinding_grants_secrets_access_cluster_wide():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    cluster_role = builders.role(
        name="secret-reader", kind="ClusterRole", rules=[{"resources": ["secrets"], "verbs": ["get"]}]
    )
    binding = builders.role_binding(
        kind="ClusterRoleBinding",
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="ClusterRole",
        role_ref_name="secret-reader",
    )

    graph = build_graph([pod, service, cluster_role, binding])

    role_id = role_node(None, "ClusterRole", "secret-reader")
    assert graph.has_edge(role_id, secrets_node(None))


def test_a_narrowly_bound_clusterrole_grant_does_not_inherit_a_wider_grant_bound_elsewhere():
    # Regression test: the same ClusterRole bound twice, once scoped to
    # team-a through a RoleBinding, once cluster-wide through an unrelated
    # ClusterRoleBinding for a different ServiceAccount. Before this was
    # fixed, both bindings' capability edges landed on one shared role
    # node keyed only by the ClusterRole's own identity, so team-a's
    # ServiceAccount ended up with a path to secrets in every namespace,
    # a grant it was never actually given.
    narrow_pod = builders.pod(
        name="app", namespace="team-a", labels={"app": "web"}, service_account_name="app-sa"
    )
    narrow_service = builders.service(
        namespace="team-a", service_type="LoadBalancer", selector={"app": "web"}
    )
    cluster_role = builders.role(
        name="secret-reader", kind="ClusterRole", rules=[{"resources": ["secrets"], "verbs": ["get"]}]
    )
    narrow_binding = builders.role_binding(
        namespace="team-a",
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "team-a"}],
        role_ref_kind="ClusterRole",
        role_ref_name="secret-reader",
    )
    wide_binding = builders.role_binding(
        name="wide-binding",
        kind="ClusterRoleBinding",
        subjects=[{"kind": "ServiceAccount", "name": "other-sa", "namespace": "default"}],
        role_ref_kind="ClusterRole",
        role_ref_name="secret-reader",
    )
    other_pod = builders.pod(
        name="other", namespace="default", labels={"app": "other"}, service_account_name="other-sa"
    )
    other_service = builders.service(
        namespace="default", service_type="LoadBalancer", selector={"app": "other"}
    )

    graph = build_graph(
        [narrow_pod, narrow_service, other_pod, other_service, cluster_role, narrow_binding, wide_binding]
    )

    narrow_sa = service_account_node("team-a", "app-sa")
    wide_sa = service_account_node("default", "other-sa")

    assert nx.has_path(graph, narrow_sa, secrets_node("team-a"))
    assert not nx.has_path(graph, narrow_sa, secrets_node(None))
    assert nx.has_path(graph, wide_sa, secrets_node(None))


def test_hostpath_plus_privileged_reaches_node_breakout():
    pod = builders.pod(
        name="app",
        labels={"app": "web"},
        containers=[{"name": "app", "securityContext": {"privileged": True}}],
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
    )
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    edge = graph.edges[workload_node(pod), NODE_BREAKOUT]
    assert edge["confidence"] == "theoretical"


def test_hostpath_alone_without_privileged_does_not_reach_node_breakout():
    pod = builders.pod(
        name="app",
        labels={"app": "web"},
        containers=[{"name": "app"}],
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
    )
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    graph = build_graph([pod, service])

    assert not graph.has_edge(workload_node(pod), NODE_BREAKOUT)


def test_no_rbac_grant_means_no_secrets_or_admin_edge():
    pod = builders.pod(name="app", labels={"app": "web"}, service_account_name="app-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    role = builders.role(name="reader", rules=[{"resources": ["configmaps"], "verbs": ["get"]}])
    binding = builders.role_binding(
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "default"}],
        role_ref_kind="Role",
        role_ref_name="reader",
    )

    graph = build_graph([pod, service, role, binding])

    role_id = role_node("default", "Role", "reader")
    assert not graph.has_edge(role_id, CLUSTER_ADMIN)
    assert not any(edge[1].startswith("secrets:") for edge in graph.out_edges(role_id))
