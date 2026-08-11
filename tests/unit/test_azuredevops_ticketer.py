from datetime import UTC, datetime

import pytest

from kubesentinel.integrations import azuredevops as azuredevops_module
from kubesentinel.integrations.azuredevops import AzureDevOpsTicketer
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


def _ticketer() -> AzureDevOpsTicketer:
    return AzureDevOpsTicketer(organization="acme", project="platform", personal_access_token="pat123")


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_is_configured_requires_org_project_and_pat():
    assert _ticketer().is_configured() is True
    assert AzureDevOpsTicketer(organization="acme").is_configured() is False


def test_missing_configuration_raises_before_any_request(monkeypatch):
    called = []
    monkeypatch.setattr(azuredevops_module.requests, "post", lambda *a, **k: called.append(1))

    with pytest.raises(TicketError, match="not configured"):
        AzureDevOpsTicketer().file_finding(_finding())
    assert not called


def test_file_finding_returns_the_work_item_id_and_web_url(monkeypatch):
    payload = {"id": 555, "_links": {"html": {"href": "https://dev.azure.com/acme/platform/_workitems/edit/555"}}}
    monkeypatch.setattr(azuredevops_module.requests, "post", lambda *a, **k: _FakeResponse(200, payload))

    result = _ticketer().file_finding(_finding())

    assert result.ticketer == "azuredevops"
    assert result.key == "555"
    assert result.url == "https://dev.azure.com/acme/platform/_workitems/edit/555"


def test_request_is_a_json_patch_document_with_title_and_description(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, **kwargs):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse(200, {"id": 1})

    monkeypatch.setattr(azuredevops_module.requests, "post", fake_post)
    _ticketer().file_finding(_finding())

    assert "acme" in captured["url"]
    assert "platform" in captured["url"]
    assert captured["headers"]["Content-Type"] == "application/json-patch+json"
    fields = {entry["path"]: entry["value"] for entry in captured["json"]}
    assert "Privileged container" in fields["/fields/System.Title"]


def test_critical_risk_maps_to_the_critical_severity_field(monkeypatch):
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["json"] = json
        return _FakeResponse(200, {"id": 1})

    monkeypatch.setattr(azuredevops_module.requests, "post", fake_post)
    _ticketer().file_finding(_finding(risk="critical"))

    fields = {entry["path"]: entry["value"] for entry in captured["json"]}
    assert fields["/fields/Microsoft.VSTS.Common.Severity"] == "1 - Critical"


def test_a_rejected_request_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(
        azuredevops_module.requests, "post", lambda *a, **k: _FakeResponse(401, text="unauthorized")
    )
    with pytest.raises(TicketError, match="401"):
        _ticketer().file_finding(_finding())


def test_a_connection_failure_raises_ticket_error(monkeypatch):
    def raise_connection_error(*args, **kwargs):
        raise azuredevops_module.requests.ConnectionError("could not connect")

    monkeypatch.setattr(azuredevops_module.requests, "post", raise_connection_error)
    with pytest.raises(TicketError, match="could not reach Azure DevOps"):
        _ticketer().file_finding(_finding())


def test_a_response_missing_a_work_item_id_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(azuredevops_module.requests, "post", lambda *a, **k: _FakeResponse(200, {}))
    with pytest.raises(TicketError, match="did not include a work item id"):
        _ticketer().file_finding(_finding())
