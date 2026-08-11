from datetime import UTC, datetime

import pytest

from kubesentinel.integrations import jira as jira_module
from kubesentinel.integrations.jira import JiraTicketer
from kubesentinel.integrations.ticketer import TicketError
from kubesentinel.models.finding import Evidence, Finding


def _finding(risk: str = "high") -> Finding:
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


def _ticketer() -> JiraTicketer:
    return JiraTicketer(
        base_url="https://acme.atlassian.net",
        email="bot@acme.example",
        api_token="token123",
        project_key="SEC",
    )


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_is_configured_requires_all_four_settings():
    assert _ticketer().is_configured() is True
    assert JiraTicketer(base_url="https://acme.atlassian.net").is_configured() is False


def test_missing_configuration_raises_before_any_request(monkeypatch):
    called = []
    monkeypatch.setattr(jira_module.requests, "post", lambda *a, **k: called.append(1))

    with pytest.raises(TicketError, match="not configured"):
        JiraTicketer().file_finding(_finding())
    assert not called


def test_file_finding_returns_the_created_issue_key_and_browse_url(monkeypatch):
    monkeypatch.setattr(
        jira_module.requests, "post", lambda *a, **k: _FakeResponse(201, {"key": "SEC-42"})
    )

    result = _ticketer().file_finding(_finding())

    assert result.ticketer == "jira"
    assert result.key == "SEC-42"
    assert result.url == "https://acme.atlassian.net/browse/SEC-42"


def test_request_carries_the_project_key_and_summary(monkeypatch):
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse(201, {"key": "SEC-1"})

    monkeypatch.setattr(jira_module.requests, "post", fake_post)
    _ticketer().file_finding(_finding())

    assert captured["url"] == "https://acme.atlassian.net/rest/api/2/issue"
    assert captured["json"]["fields"]["project"]["key"] == "SEC"
    assert "Privileged container" in captured["json"]["fields"]["summary"]


def test_a_rejected_request_raises_ticket_error_with_the_status_and_body(monkeypatch):
    monkeypatch.setattr(
        jira_module.requests,
        "post",
        lambda *a, **k: _FakeResponse(400, {"errorMessages": ["project key is required"]}),
    )
    with pytest.raises(TicketError, match="400"):
        _ticketer().file_finding(_finding())


def test_a_connection_failure_raises_ticket_error(monkeypatch):
    def raise_connection_error(*args, **kwargs):
        raise jira_module.requests.ConnectionError("could not connect")

    monkeypatch.setattr(jira_module.requests, "post", raise_connection_error)
    with pytest.raises(TicketError, match="could not reach Jira"):
        _ticketer().file_finding(_finding())


def test_a_response_missing_the_issue_key_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(jira_module.requests, "post", lambda *a, **k: _FakeResponse(201, {}))
    with pytest.raises(TicketError, match="did not include an issue key"):
        _ticketer().file_finding(_finding())
