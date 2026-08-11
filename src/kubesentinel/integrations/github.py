"""Files a KubeSentinel finding as a GitHub issue using the gh CLI.

Shells out to `gh` the same way TrivyAdapter shells out to `trivy`: reuse
whatever the environment already has authenticated rather than asking
KubeSentinel to hold its own GitHub credentials. If `gh auth login` has
already run, this just works.
"""

import shutil
import subprocess

from kubesentinel.gitops import GitOpsSource
from kubesentinel.integrations.ticketer import (
    TicketError,
    TicketResult,
    build_ticket_body,
    build_ticket_title,
)
from kubesentinel.models.finding import Finding


class GitHubTicketer:
    name = "github"

    def __init__(
        self, repo: str | None = None, binary: str = "gh", timeout_seconds: int = 30
    ) -> None:
        self.repo = repo
        self.binary = binary
        self.timeout_seconds = timeout_seconds

    def is_configured(self) -> bool:
        return shutil.which(self.binary) is not None

    def file_finding(
        self, finding: Finding, gitops_source: GitOpsSource | None = None
    ) -> TicketResult:
        command = [
            self.binary,
            "issue",
            "create",
            "--title",
            build_ticket_title(finding),
            "--body",
            build_ticket_body(finding, gitops_source),
        ]
        if self.repo:
            command += ["--repo", self.repo]

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.timeout_seconds, check=False
            )
        except FileNotFoundError as error:
            raise TicketError(f"{self.binary} is not installed or not on PATH") from error
        except subprocess.TimeoutExpired as error:
            raise TicketError(
                f"filing a GitHub issue took longer than {self.timeout_seconds}s"
            ) from error

        if result.returncode != 0:
            raise TicketError(f"gh exited {result.returncode}: {_last_line(result.stderr)}")

        url = _last_line(result.stdout)
        if not url.startswith("http"):
            raise TicketError(
                f"gh issue create did not return an issue URL: {url or '(no output)'}"
            )

        key = url.rstrip("/").rsplit("/", 1)[-1]
        return TicketResult(ticketer=self.name, key=key, url=url)


def _last_line(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[-1] if stripped else ""
