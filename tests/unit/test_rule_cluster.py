from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from tests.fixtures import builders

RULES = load_rules()

APISERVER_LABELS = {"component": "kube-apiserver", "tier": "control-plane"}


def _fires(rule_id: str, resource) -> bool:
    rule = next(r for r in RULES if r.id == rule_id)
    findings = evaluate([resource], [rule], cluster_name="test")
    return len(findings) == 1


def test_anonymous_auth_not_disabled():
    bad = builders.pod(
        labels=APISERVER_LABELS,
        containers=[{"name": "kube-apiserver", "command": ["kube-apiserver", "--advertise-address=10.0.0.1"]}],
    )
    good = builders.pod(
        labels=APISERVER_LABELS,
        containers=[{"name": "kube-apiserver", "command": ["kube-apiserver", "--anonymous-auth=false"]}],
    )
    assert _fires("KS-CLUSTER-001", bad)
    assert not _fires("KS-CLUSTER-001", good)


def test_profiling_enabled():
    bad = builders.pod(
        labels=APISERVER_LABELS,
        containers=[{"name": "kube-apiserver", "command": ["kube-apiserver", "--profiling=true"]}],
    )
    good = builders.pod(
        labels=APISERVER_LABELS,
        containers=[{"name": "kube-apiserver", "command": ["kube-apiserver"]}],
    )
    assert _fires("KS-CLUSTER-002", bad)
    assert not _fires("KS-CLUSTER-002", good)


def test_cluster_rules_do_not_fire_on_a_regular_pod():
    # Same insecure command line, but without the kube-apiserver labels, this
    # is just some other pod that happens to share an argument string, the
    # match_labels selector should keep the rule from touching it.
    regular_pod = builders.pod(
        containers=[{"name": "app", "command": ["kube-apiserver", "--profiling=true"]}]
    )
    assert not _fires("KS-CLUSTER-001", regular_pod)
    assert not _fires("KS-CLUSTER-002", regular_pod)
