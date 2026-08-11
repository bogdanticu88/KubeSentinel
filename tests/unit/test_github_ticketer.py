import subprocess
from datetime import UTC, datetime

import pytest

from kubesentinel.integrations import github as github_module
from kubesentinel.integrations.github import GitHubTicketer
from kubesentinel.integrations.ticketer import TicketError
from kubesentinel.models.finding import Evidence, Finding


def _finding() -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="KS-test-001",
        rule_id="KS-WORKLOAD-001",
        category="workloads",
        dimension="workloads",
        severity="critical",
        risk="critical",
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


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_is_available_reflects_whether_gh_is_on_path(monkeypatch):
    monkeypatch.setattr(github_module.shutil, "which", lambda name: "/usr/local/bin/gh")
    assert GitHubTicketer().is_configured() is True

    monkeypatch.setattr(github_module.shutil, "which", lambda name: None)
    assert GitHubTicketer().is_configured() is False


def test_file_finding_returns_the_created_issue_url(monkeypatch):
    monkeypatch.setattr(
        github_module.subprocess,
        "run",
        lambda *a, **k: _completed(stdout="https://github.com/acme/repo/issues/42\n"),
    )

    result = GitHubTicketer().file_finding(_finding())

    assert result.ticketer == "github"
    assert result.key == "42"
    assert result.url == "https://github.com/acme/repo/issues/42"


def test_repo_flag_is_passed_through_when_set(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return _completed(stdout="https://github.com/acme/repo/issues/1\n")

    monkeypatch.setattr(github_module.subprocess, "run", fake_run)
    GitHubTicketer(repo="acme/repo").file_finding(_finding())

    assert "--repo" in captured["command"]
    assert "acme/repo" in captured["command"]


def test_nonzero_exit_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(
        github_module.subprocess,
        "run",
        lambda *a, **k: _completed(returncode=1, stderr="X could not find a repository"),
    )
    with pytest.raises(TicketError, match="exited 1"):
        GitHubTicketer().file_finding(_finding())


def test_missing_binary_raises_ticket_error(monkeypatch):
    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(github_module.subprocess, "run", raise_not_found)
    with pytest.raises(TicketError, match="not installed"):
        GitHubTicketer().file_finding(_finding())


def test_timeout_raises_ticket_error(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="gh", timeout=1)

    monkeypatch.setattr(github_module.subprocess, "run", raise_timeout)
    with pytest.raises(TicketError, match="longer than"):
        GitHubTicketer(timeout_seconds=1).file_finding(_finding())


def test_output_with_no_recognizable_url_raises_ticket_error(monkeypatch):
    monkeypatch.setattr(
        github_module.subprocess, "run", lambda *a, **k: _completed(stdout="something unexpected")
    )
    with pytest.raises(TicketError, match="did not return an issue URL"):
        GitHubTicketer().file_finding(_finding())
