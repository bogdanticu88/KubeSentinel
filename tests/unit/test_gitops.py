from kubesentinel.gitops import detect_all, detect_source, find_source
from tests.fixtures import builders


def test_argocd_instance_label_is_detected():
    resource = builders.deployment(name="app")
    resource = resource.model_copy(update={"labels": {"argocd.argoproj.io/instance": "payments-app"}})

    source = detect_source(resource)

    assert source is not None
    assert source.tool == "argocd"
    assert source.name == "payments-app"
    assert source.namespace is None


def test_flux_kustomization_labels_are_detected():
    resource = builders.deployment(name="app")
    resource = resource.model_copy(
        update={
            "labels": {
                "kustomize.toolkit.fluxcd.io/name": "payments-kustomization",
                "kustomize.toolkit.fluxcd.io/namespace": "flux-system",
            }
        }
    )

    source = detect_source(resource)

    assert source is not None
    assert source.tool == "flux"
    assert source.name == "payments-kustomization"
    assert source.namespace == "flux-system"


def test_flux_helmrelease_labels_are_detected_as_a_fallback():
    resource = builders.deployment(name="app")
    resource = resource.model_copy(
        update={
            "labels": {
                "helm.toolkit.fluxcd.io/name": "payments-release",
                "helm.toolkit.fluxcd.io/namespace": "flux-system",
            }
        }
    )

    source = detect_source(resource)

    assert source is not None
    assert source.tool == "flux"
    assert source.name == "payments-release"


def test_argocd_label_wins_when_both_are_somehow_present():
    resource = builders.deployment(name="app")
    resource = resource.model_copy(
        update={
            "labels": {
                "argocd.argoproj.io/instance": "payments-app",
                "kustomize.toolkit.fluxcd.io/name": "payments-kustomization",
            }
        }
    )

    source = detect_source(resource)

    assert source is not None
    assert source.tool == "argocd"


def test_a_resource_with_no_gitops_labels_is_unmanaged():
    resource = builders.deployment(name="app")
    assert detect_source(resource) is None


def test_find_source_matches_by_kind_name_and_namespace():
    managed = builders.deployment(name="app", namespace="payments")
    managed = managed.model_copy(update={"labels": {"argocd.argoproj.io/instance": "payments-app"}})
    other = builders.deployment(name="other", namespace="payments")

    source = find_source("Deployment", "app", "payments", [managed, other])

    assert source is not None
    assert source.name == "payments-app"


def test_find_source_returns_none_when_no_resource_matches():
    resources = [builders.deployment(name="app", namespace="payments")]
    assert find_source("Deployment", "missing", "payments", resources) is None


def test_detect_all_only_considers_workload_kinds():
    workload = builders.deployment(name="app")
    workload = workload.model_copy(update={"labels": {"argocd.argoproj.io/instance": "payments-app"}})
    service = builders.service(name="svc")

    statuses = detect_all([workload, service])

    assert len(statuses) == 1
    assert statuses[0].kind == "Deployment"
    assert statuses[0].source is not None
    assert statuses[0].source.tool == "argocd"
