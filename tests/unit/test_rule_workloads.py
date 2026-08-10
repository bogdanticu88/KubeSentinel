import pytest

from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from tests.fixtures import builders

RULES = load_rules()


def _fires(rule_id: str, resource) -> bool:
    rule = next(r for r in RULES if r.id == rule_id)
    findings = evaluate([resource], [rule], cluster_name="test")
    return len(findings) == 1


def test_privileged_container():
    bad = builders.pod(containers=[{"name": "app", "securityContext": {"privileged": True}}])
    good = builders.pod(containers=[{"name": "app", "securityContext": {"privileged": False}}])
    assert _fires("KS-WORKLOAD-001", bad)
    assert not _fires("KS-WORKLOAD-001", good)


def test_run_as_non_root():
    bad = builders.pod(containers=[{"name": "app"}])
    good = builders.pod(containers=[{"name": "app", "securityContext": {"runAsNonRoot": True}}])
    assert _fires("KS-WORKLOAD-002", bad)
    assert not _fires("KS-WORKLOAD-002", good)


def test_privilege_escalation():
    bad = builders.pod(containers=[{"name": "app", "securityContext": {"allowPrivilegeEscalation": True}}])
    good = builders.pod(containers=[{"name": "app", "securityContext": {"allowPrivilegeEscalation": False}}])
    assert _fires("KS-WORKLOAD-003", bad)
    assert not _fires("KS-WORKLOAD-003", good)


def test_dangerous_capabilities():
    bad = builders.pod(
        containers=[{"name": "app", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]
    )
    good = builders.pod(
        containers=[{"name": "app", "securityContext": {"capabilities": {"add": ["CHOWN"]}}}]
    )
    assert _fires("KS-WORKLOAD-004", bad)
    assert not _fires("KS-WORKLOAD-004", good)


def test_host_network():
    assert _fires("KS-WORKLOAD-005", builders.pod(host_network=True))
    assert not _fires("KS-WORKLOAD-005", builders.pod(host_network=False))


def test_host_pid():
    assert _fires("KS-WORKLOAD-006", builders.pod(host_pid=True))
    assert not _fires("KS-WORKLOAD-006", builders.pod(host_pid=False))


def test_host_ipc():
    assert _fires("KS-WORKLOAD-007", builders.pod(host_ipc=True))
    assert not _fires("KS-WORKLOAD-007", builders.pod(host_ipc=False))


def test_hostpath_volume():
    bad = builders.pod(volumes=[{"name": "data", "hostPath": {"path": "/var/run/docker.sock"}}])
    good = builders.pod(volumes=[{"name": "data", "emptyDir": {}}])
    assert _fires("KS-WORKLOAD-008", bad)
    assert not _fires("KS-WORKLOAD-008", good)


def test_missing_security_context():
    bad = builders.pod(containers=[{"name": "app"}])
    good = builders.pod(containers=[{"name": "app", "securityContext": {}}])
    assert _fires("KS-WORKLOAD-009", bad)
    assert not _fires("KS-WORKLOAD-009", good)


def test_writable_root_filesystem():
    bad = builders.pod(containers=[{"name": "app", "securityContext": {"readOnlyRootFilesystem": False}}])
    good = builders.pod(containers=[{"name": "app", "securityContext": {"readOnlyRootFilesystem": True}}])
    assert _fires("KS-WORKLOAD-010", bad)
    assert not _fires("KS-WORKLOAD-010", good)


@pytest.mark.parametrize("builder", [builders.deployment, builders.cron_job])
def test_workload_rules_apply_regardless_of_workload_kind(builder):
    bad = builder(containers=[{"name": "app", "securityContext": {"privileged": True}}])
    assert _fires("KS-WORKLOAD-001", bad)
