from pathlib import Path

import pytest

from kubesentinel.engines.misconfiguration.loader import RuleLoadError, load_rules

EXPECTED_RULE_IDS = {
    "KS-WORKLOAD-001", "KS-WORKLOAD-002", "KS-WORKLOAD-003", "KS-WORKLOAD-004",
    "KS-WORKLOAD-005", "KS-WORKLOAD-006", "KS-WORKLOAD-007", "KS-WORKLOAD-008",
    "KS-WORKLOAD-009", "KS-WORKLOAD-010",
    "KS-RBAC-001", "KS-RBAC-002", "KS-RBAC-003", "KS-RBAC-004", "KS-RBAC-005",
    "KS-NET-001", "KS-NET-002", "KS-NET-003", "KS-NET-004",
}


def test_packaged_rules_load_and_validate():
    rules = load_rules()
    assert {rule.id for rule in rules} == EXPECTED_RULE_IDS


def test_every_rule_has_a_non_empty_remediation_and_rationale():
    for rule in load_rules():
        assert rule.remediation.strip(), rule.id
        assert rule.risk_rationale.strip(), rule.id
        assert rule.description.strip(), rule.id


def test_resource_match_rules_have_a_selector_and_conditions():
    for rule in load_rules():
        if rule.type == "resource_match":
            assert rule.selector is not None and rule.selector.kinds, rule.id
            assert rule.conditions, rule.id


def test_disabled_rule_is_excluded(tmp_path: Path):
    _write_rule(
        tmp_path,
        "disabled.yaml",
        {
            "id": "KS-TEST-001",
            "name": "disabled rule",
            "category": "workloads",
            "dimension": "workloads",
            "severity": "low",
            "enabled": False,
            "description": "test",
            "selector": {"kinds": ["Pod"]},
            "conditions": [{"field": "x", "operator": "exists"}],
            "risk_rationale": "test",
            "remediation": "test",
        },
    )
    assert load_rules(tmp_path) == []


def test_duplicate_rule_id_raises(tmp_path: Path):
    body = {
        "id": "KS-TEST-002",
        "name": "dup",
        "category": "workloads",
        "dimension": "workloads",
        "severity": "low",
        "description": "test",
        "selector": {"kinds": ["Pod"]},
        "conditions": [{"field": "x", "operator": "exists"}],
        "risk_rationale": "test",
        "remediation": "test",
    }
    _write_rule(tmp_path, "a.yaml", body)
    _write_rule(tmp_path, "b.yaml", body)
    with pytest.raises(RuleLoadError, match="duplicate rule id"):
        load_rules(tmp_path)


def test_invalid_yaml_raises(tmp_path: Path):
    (tmp_path / "broken.yaml").write_text("id: [unterminated", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="invalid YAML"):
        load_rules(tmp_path)


def test_schema_violation_raises(tmp_path: Path):
    _write_rule(tmp_path, "bad.yaml", {"id": "KS-TEST-003", "name": "missing required fields"})
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def _write_rule(tmp_path: Path, filename: str, body: dict) -> None:
    import yaml

    (tmp_path / filename).write_text(yaml.safe_dump(body), encoding="utf-8")
