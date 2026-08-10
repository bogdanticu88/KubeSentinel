import pytest

from kubesentinel.engines.misconfiguration.paths import evaluate_condition, resolve
from kubesentinel.models.rule import RuleCondition


def test_resolve_simple_key():
    assert resolve({"hostNetwork": True}, "hostNetwork") == [True]


def test_resolve_nested_key():
    data = {"securityContext": {"privileged": True}}
    assert resolve(data, "securityContext.privileged") == [True]


def test_resolve_missing_key_returns_empty():
    assert resolve({"foo": 1}, "bar") == []
    assert resolve({"foo": {"bar": 1}}, "foo.baz") == []


def test_resolve_array_segment_yields_one_value_per_element():
    data = {"containers": [{"name": "a"}, {"name": "b"}]}
    assert resolve(data, "containers[].name") == ["a", "b"]


def test_resolve_array_segment_with_missing_field_on_some_elements():
    data = {"containers": [{"securityContext": {"privileged": True}}, {"name": "no-context"}]}
    assert resolve(data, "containers[].securityContext.privileged") == [True]


def test_resolve_array_of_non_dicts_for_contains_style_use():
    data = {"rules": [{"resources": ["pods", "*"]}]}
    assert resolve(data, "rules[].resources") == [["pods", "*"]]


def test_resolve_missing_array_key_returns_empty():
    assert resolve({}, "containers[].name") == []


def test_evaluate_equals_true():
    condition = RuleCondition(field="hostNetwork", operator="equals", value=True)
    assert evaluate_condition({"hostNetwork": True}, condition) is True
    assert evaluate_condition({"hostNetwork": False}, condition) is False
    assert evaluate_condition({}, condition) is False


def test_evaluate_not_equals_treats_missing_field_as_a_match():
    # allowPrivilegeEscalation defaults to true when unset, so "not_equals false"
    # should flag both an explicit true and a container that never set the field.
    condition = RuleCondition(field="securityContext.allowPrivilegeEscalation", operator="not_equals", value=False)
    assert evaluate_condition({"securityContext": {"allowPrivilegeEscalation": True}}, condition) is True
    assert evaluate_condition({"securityContext": {}}, condition) is True
    assert evaluate_condition({}, condition) is True
    assert evaluate_condition({"securityContext": {"allowPrivilegeEscalation": False}}, condition) is False


def test_evaluate_exists_and_not_exists():
    exists = RuleCondition(field="volumes[].hostPath", operator="exists")
    not_exists = RuleCondition(field="containers[].securityContext", operator="not_exists")

    data_with_hostpath = {"volumes": [{"name": "v1", "hostPath": {"path": "/etc"}}]}
    assert evaluate_condition(data_with_hostpath, exists) is True
    assert evaluate_condition({"volumes": [{"name": "v1"}]}, exists) is False

    data_missing_context = {"containers": [{"name": "app"}]}
    assert evaluate_condition(data_missing_context, not_exists) is True
    data_with_context = {"containers": [{"name": "app", "securityContext": {}}]}
    assert evaluate_condition(data_with_context, not_exists) is False


def test_evaluate_contains():
    condition = RuleCondition(field="rules[].resources", operator="contains", value="*")
    assert evaluate_condition({"rules": [{"resources": ["*"]}]}, condition) is True
    assert evaluate_condition({"rules": [{"resources": ["pods"]}]}, condition) is False


def test_evaluate_intersects():
    condition = RuleCondition(field="rules[].verbs", operator="intersects", value=["escalate", "bind"])
    assert evaluate_condition({"rules": [{"verbs": ["get", "escalate"]}]}, condition) is True
    assert evaluate_condition({"rules": [{"verbs": ["get", "list"]}]}, condition) is False


def test_evaluate_quantifier_any_vs_all():
    data = {"containers": [{"securityContext": {"privileged": True}}, {"securityContext": {"privileged": False}}]}
    any_condition = RuleCondition(
        field="containers[].securityContext.privileged", operator="equals", value=True, quantifier="any"
    )
    all_condition = RuleCondition(
        field="containers[].securityContext.privileged", operator="equals", value=True, quantifier="all"
    )
    assert evaluate_condition(data, any_condition) is True
    assert evaluate_condition(data, all_condition) is False


def test_evaluate_unknown_operator_raises():
    condition = RuleCondition.model_construct(field="x", operator="bogus", value=None, quantifier="any")
    with pytest.raises(ValueError):
        evaluate_condition({"x": 1}, condition)
