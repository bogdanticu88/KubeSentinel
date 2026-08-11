from datetime import UTC, datetime

import pytest

from kubesentinel.integrations import servicenow as servicenow_module
from kubesentinel.integrations.servicenow import ServiceNowTicketer
from kubesentinel.integrations.ticketer import TicketError
from kubesentinel.models.finding import Evidence, Finding


def _finding(risk: str = "critical") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="KS-test-001",
        rule_id="KS-WORKLOAD-001",
        category="workloads",
        dimension="workloads",
        severity=risk,
        risk=risk,
        cluster="kind-test",
        namespace="payments",
        resource="payments-api",
        resource_kind="Deployment",
        title="Privileged container",
        description="A container runs privileged.",
        risk_rationale="test",
        remediation="Set privileged: false.",
        evidence=Evidence(resource_kind="Deployment", resource_name="payments-api", namespace="payments"),
        first_seen=now,
        last_seen=now,
    )


def _ticketer() -> ServiceNowTicketer:
    return ServiceNowTicketer(instance="acmedev", username="bot", password="secret")


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_is_configured_requires_instance_username_and_password():
    assert _ticketer().is_configured() is True
    assert ServiceNowTicketer(instance="acmedev").is_configured() is False


def test_missing_configuration_raises_before_any_request(monkeypatch):
    called = []
    monkeypatch.setattr(servicenow_module.requests, "post", lambda *a, **k: called.append(1))

    with pytest.raises(TicketError, match="not configured"):
        ServiceNowTicketer().file_finding(_finding())
    assert not called


def test_file_finding_returns_the_incident_number_and_a_navigable_url(monkeypatch):
    monkeypatch.setattr(
        servicenow_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(201, {"result": {"number": "INC0012345", "sys_id": "abc123"}}),
    )

    result = _ticketer().file_finding(_finding())

    assert result.ticketer == "servicenow"
    assert result.key == "INC0012345"
    assert result.url is not None
    assert "abc123" in result.url


def test_critical_risk_maps_to_the_highest_urgency_and_impact(monkeypatch):
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["json"] = json
        return _FakeResponse(201, {"result": {"number": "INC1", "sys_id": "x"}})

    monkeypatch.setattr(servicenow_module.requests, "post", fake_post)
    _ticketer().file_finding(_finding(risk="critical"))

    assert captured["json"]["urgency"] == "1"
    assert captured["json"]["impact"] == "1"


def test_a_rejected_request_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(
        servicenow_module.requests, "post", lambda *a, **k: _FakeResponse(401, text="unauthorized")
    )
    with pytest.raises(TicketError, match="401"):
        _ticketer().file_finding(_finding())


def test_a_connection_failure_raises_ticket_error(monkeypatch):
    def raise_connection_error(*args, **kwargs):
        raise servicenow_module.requests.ConnectionError("could not connect")

    monkeypatch.setattr(servicenow_module.requests, "post", raise_connection_error)
    with pytest.raises(TicketError, match="could not reach ServiceNow"):
        _ticketer().file_finding(_finding())


def test_a_response_missing_the_incident_number_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(
        servicenow_module.requests, "post", lambda *a, **k: _FakeResponse(201, {"result": {}})
    )
    with pytest.raises(TicketError, match="did not include an incident number"):
        _ticketer().file_finding(_finding())
