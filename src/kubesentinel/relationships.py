"""Structural relationship joins shared by the risk correlation engine and
the attack-path graph.

Both walk the same underlying facts: which Service exposes which workload,
which ServiceAccount a workload runs as, which Role a Binding actually
attaches to it, and what an RBAC rule grants. Correlation stops after one
hop and turns it into a risk adjustment, the graph keeps going and turns it
into edges. No reason to compute the same joins twice in two places.
"""

from kubesentinel.models.resource import CollectedResource

SECRET_READ_VERBS = {"get", "list", "watch", "*"}
ESCALATION_VERBS = {"escalate", "bind", "impersonate"}

# (namespace, kind, name) identifies a Role or ClusterRole, namespace is
# None for a ClusterRole since it has none.
RoleKey = tuple[str | None, str, str]
RoleRules = dict[RoleKey, list[dict]]


def pod_template_labels(workload: CollectedResource) -> dict[str, str]:
    # A Service selector matches a pod's own labels, not its owning
    # Deployment's labels, those are frequently different. A bare Pod's own
    # metadata.labels already are those labels, everything else nests its
    # pod template somewhere under spec, one level deeper for CronJob.
    if workload.kind == "Pod":
        return workload.labels
    spec = workload.raw.get("spec") or {}
    if workload.kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        spec = spec.get("template") or {}
    return (spec.get("metadata") or {}).get("labels") or {}


def ingress_backend_service_names(ingress_data: dict) -> set[str]:
    names: set[str] = set()
    default_backend = (ingress_data.get("defaultBackend") or {}).get("service") or {}
    if default_backend.get("name"):
        names.add(default_backend["name"])
    for rule in ingress_data.get("rules") or []:
        for path in (rule.get("http") or {}).get("paths") or []:
            backend_service = (path.get("backend") or {}).get("service") or {}
            if backend_service.get("name"):
                names.add(backend_service["name"])
    return names


def exposed_selectors(resources: list[CollectedResource]) -> list[tuple[str | None, dict]]:
    """(namespace, selector) for every Service reachable from outside the
    cluster, either directly (LoadBalancer, NodePort) or as an Ingress
    backend behind a Service of any type."""
    ingress_backends: dict[str | None, set[str]] = {}
    for resource in resources:
        if resource.kind != "Ingress":
            continue
        names = ingress_backends.setdefault(resource.namespace, set())
        names.update(ingress_backend_service_names(resource.data))

    selectors = []
    for resource in resources:
        if resource.kind != "Service":
            continue
        selector = resource.data.get("selector") or {}
        if not selector:
            continue
        exposed_type = resource.data.get("type") in ("LoadBalancer", "NodePort")
        exposed_via_ingress = resource.name in ingress_backends.get(resource.namespace, set())
        if exposed_type or exposed_via_ingress:
            selectors.append((resource.namespace, selector))
    return selectors


def is_exposed(workload: CollectedResource, selectors: list[tuple[str | None, dict]]) -> bool:
    labels = pod_template_labels(workload)
    for namespace, selector in selectors:
        if namespace == workload.namespace and selector.items() <= labels.items():
            return True
    return False


def role_rules(resources: list[CollectedResource]) -> RoleRules:
    rules: RoleRules = {}
    for resource in resources:
        if resource.kind not in ("Role", "ClusterRole"):
            continue
        namespace = resource.namespace if resource.kind == "Role" else None
        rules[(namespace, resource.kind, resource.name)] = resource.data.get("rules") or []
    return rules


def binding_targets_service_account(
    binding: CollectedResource, sa_namespace: str | None, sa_name: str
) -> bool:
    for subject in binding.data.get("subjects") or []:
        if subject.get("kind") != "ServiceAccount" or subject.get("name") != sa_name:
            continue
        subject_namespace = subject.get("namespace") or binding.namespace
        if subject_namespace == sa_namespace:
            return True
    return False


def bound_roles(
    sa_namespace: str | None,
    sa_name: str,
    bindings: list[CollectedResource],
    rules: RoleRules,
) -> list[RoleKey]:
    """Every Role or ClusterRole key actually bound to this ServiceAccount."""
    keys = []
    for binding in bindings:
        if not binding_targets_service_account(binding, sa_namespace, sa_name):
            continue
        role_ref = binding.data.get("roleRef") or {}
        role_kind, role_name = role_ref.get("kind"), role_ref.get("name")
        if not role_kind or not role_name:
            continue
        role_namespace = binding.namespace if role_kind == "Role" else None
        key = (role_namespace, role_kind, role_name)
        if key in rules:
            keys.append(key)
    return keys


def has_wildcard(rule: dict) -> bool:
    return "*" in (rule.get("resources") or []) or "*" in (rule.get("verbs") or [])


def grants_secret_read(rule: dict) -> bool:
    resources = rule.get("resources") or []
    verbs = set(rule.get("verbs") or [])
    return ("secrets" in resources or "*" in resources) and bool(verbs & SECRET_READ_VERBS)


def grants_escalation(rule: dict) -> bool:
    return bool(set(rule.get("verbs") or []) & ESCALATION_VERBS)
