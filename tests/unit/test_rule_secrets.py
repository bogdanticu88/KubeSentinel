from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from tests.fixtures import builders

RULES = load_rules()


def _fires(rule_id: str, resource) -> bool:
    rule = next(r for r in RULES if r.id == rule_id)
    findings = evaluate([resource], [rule], cluster_name="test")
    return len(findings) == 1


def test_env_secret_reference():
    bad = builders.pod(
        containers=[
            {
                "name": "app",
                "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}],
            }
        ]
    )
    good = builders.pod(containers=[{"name": "app", "env": [{"name": "LOG_LEVEL", "value": "info"}]}])
    assert _fires("KS-SECRET-001", bad)
    assert not _fires("KS-SECRET-001", good)


def test_envfrom_secret_reference():
    bad = builders.pod(containers=[{"name": "app", "envFrom": [{"secretRef": {"name": "db-credentials"}}]}])
    good = builders.pod(containers=[{"name": "app", "envFrom": [{"configMapRef": {"name": "app-config"}}]}])
    assert _fires("KS-SECRET-002", bad)
    assert not _fires("KS-SECRET-002", good)


def test_automount_token_not_disabled():
    bad = builders.pod()
    also_bad = builders.pod(automount_service_account_token=True)
    good = builders.pod(automount_service_account_token=False)
    assert _fires("KS-SECRET-003", bad)
    assert _fires("KS-SECRET-003", also_bad)
    assert not _fires("KS-SECRET-003", good)
