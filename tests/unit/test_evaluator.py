import pytest

from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from kubesentinel.models.rule import Rule
from tests.fixtures import builders


def test_finding_id_is_deterministic_across_runs():
    resource = builders.pod(containers=[{"name": "app", "securityContext": {"privileged": True}}])
    rule = next(r for r in load_rules() if r.id == "KS-WORKLOAD-001")

    first = evaluate([resource], [rule], cluster_name="test")
    second = evaluate([resource], [rule], cluster_name="test")

    assert first[0].id == second[0].id


def test_finding_id_differs_for_different_resources():
    a = builders.pod(name="a", containers=[{"name": "app", "securityContext": {"privileged": True}}])
    b = builders.pod(name="b", containers=[{"name": "app", "securityContext": {"privileged": True}}])
    rule = next(r for r in load_rules() if r.id == "KS-WORKLOAD-001")

    findings = evaluate([a, b], [rule], cluster_name="test")
    assert findings[0].id != findings[1].id


def test_full_rule_set_against_a_small_synthetic_cluster():
    resources = [
        builders.pod(
            name="payments-api",
            namespace="payments",
            containers=[
                {"name": "app", "securityContext": {"privileged": True, "runAsNonRoot": False}}
            ],
        ),
        builders.role(name="broad-role", namespace="payments", rules=[{"resources": ["*"], "verbs": ["*"]}]),
        builders.service(name="payments-lb", namespace="payments", service_type="LoadBalancer"),
        builders.namespace("payments"),
    ]
    rules = load_rules()
    findings = evaluate(resources, rules, cluster_name="kind-local")
    fired_rule_ids = {f.rule_id for f in findings}

    assert "KS-WORKLOAD-001" in fired_rule_ids
    assert "KS-RBAC-001" in fired_rule_ids
    assert "KS-RBAC-002" in fired_rule_ids
    assert "KS-NET-002" in fired_rule_ids
    assert "KS-NET-001" in fired_rule_ids
    assert all(f.cluster == "kind-local" for f in findings)


def test_match_labels_selector_requires_every_label_to_be_present():
    rule = Rule(
        id="KS-TEST-LABELS",
        name="test label selector",
        category="test",
        dimension="configuration",
        severity="low",
        description="test",
        selector={"kinds": ["Pod"], "match_labels": {"component": "kube-apiserver"}},
        conditions=[{"field": "hostNetwork", "operator": "exists"}],
        risk_rationale="test",
        remediation="test",
    )

    matching = builders.pod(labels={"component": "kube-apiserver", "tier": "control-plane"})
    extra_labels_still_match = builders.pod(labels={"component": "kube-apiserver", "extra": "label"})
    missing_label = builders.pod(labels={"tier": "control-plane"})
    no_labels = builders.pod()

    assert len(evaluate([matching], [rule], cluster_name="test")) == 1
    assert len(evaluate([extra_labels_still_match], [rule], cluster_name="test")) == 1
    assert evaluate([missing_label], [rule], cluster_name="test") == []
    assert evaluate([no_labels], [rule], cluster_name="test") == []


def test_evaluator_rejects_an_unknown_rule_type():
    rule = next(r for r in load_rules() if r.id == "KS-WORKLOAD-001")
    rule = rule.model_copy(update={"type": "bogus"})
    resource = builders.pod()

    with pytest.raises(ValueError, match="unknown rule type"):
        evaluate([resource], [rule], cluster_name="test")
