<p align="center">
  <a href="https://github.com/bogdanticu88/KubeSentinel/actions/workflows/ci.yml"><img src="https://github.com/bogdanticu88/KubeSentinel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/bogdanticu88/KubeSentinel" alt="License"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.12%2B-blue" alt="Python Version"></a>
  <a href="#why-this-exists"><img src="https://img.shields.io/badge/core%20engine-deterministic-informational" alt="Deterministic Core"></a>
  <a href="#development"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen" alt="PRs Welcome"></a>
</p>

# KubeSentinel

Continuous Kubernetes security assurance.

KubeSentinel is not another vulnerability scanner. It answers a different question: is your
cluster still secure, what changed, and did that change open a new path for an attacker.

It combines configuration analysis, RBAC and identity analysis, network exposure analysis,
baseline drift detection, and attack path reasoning into one deterministic security model of
your cluster. No AI is required anywhere in the core engine. There is no LLM dependency and no
API key to configure. AI may show up later as an optional layer that reads KubeSentinel's
findings, it will never be the thing producing them.

## Status

Early development. `kubesentinel scan` connects to a cluster, collects security-relevant
resources, runs the misconfiguration rule set, optionally scans workload images for known
vulnerabilities with Trivy, and prints an explainable, risk-weighted score. Risk is adjusted from
a finding's raw severity based on whether its workload is exposed and what its ServiceAccount can
do, not just reported at face value. `kubesentinel snapshot` saves a scan locally, `baseline` sets
one as the reference point, and `drift` or `compare` show what changed since then and how much it
moved the score. `kubesentinel attack-paths` builds a graph from the same collected data and finds
concrete paths from the internet to secrets, cluster-admin-equivalent access, or a node breakout.
`kubesentinel audit` runs a numbered, saved audit compared against the previous one, with security
debt tracking. `kubesentinel report` writes an HTML or SARIF file. `kubesentinel ticket` files open
findings into GitHub, Jira, ServiceNow, or Azure DevOps, and `kubesentinel gitops` shows which
workloads are managed by ArgoCD or Flux. The web UI comes in a later phase; see `docs/roadmap.md`.

## Why this exists

Most Kubernetes security tools report isolated findings: a CVE here, a missing NetworkPolicy
there. That tells you what is wrong today. It does not tell you whether last week's deploy made
things worse, or whether a "medium" finding is actually reachable from the internet through three
other misconfigurations. KubeSentinel is built around that gap: state, change, context, and time,
not just a list of problems.

## Installation

Requires Python 3.12 or newer.

```bash
pip install -e ".[dev]"
```

## Usage

```bash
kubesentinel scan
```

Scans the cluster in your current kubeconfig context. Use `--context` to target a specific
cluster, `--namespace` to limit the scan, and `--output json` for machine-readable output.

```bash
kubesentinel scan --context kind-local --output json
```

Add `--with-vulnerabilities` to also scan workload images for known CVEs with
[Trivy](https://github.com/aquasecurity/trivy). This is opt-in on purpose: Trivy needs its own
database on first run and touches the network on every scan, neither of which the core
misconfiguration engine should ever require.

```bash
kubesentinel scan --with-vulnerabilities
```

### Tracking drift over time

`scan` is stateless, it prints a report and forgets it. `snapshot` does the same scan but saves
the result locally, so later runs have something to compare against.

```bash
kubesentinel baseline create --context kind-local   # scan now, set the result as the reference point
kubesentinel drift --context kind-local             # scan again, compare against the baseline
kubesentinel baseline show --context kind-local      # see what the current baseline looks like
```

`drift` always runs a fresh scan against the live cluster. Pass `--since 7d` (or `24h`, `30m`) to
compare against the nearest saved snapshot from that far back instead of the baseline.

`compare` works entirely offline, no cluster connection needed, it just diffs two snapshots
already sitting in local storage by id:

```bash
kubesentinel snapshot --context kind-local   # prints "Snapshot #12 saved..."
kubesentinel compare 9 12
```

Snapshots live in a local SQLite database, one file, no server, under
`~/.kubesentinel/kubesentinel.db` by default. Set `KUBESENTINEL_HOME` to point storage somewhere
else, mainly useful for tests or a CI job that wants its own throwaway state directory.

### Attack paths

```bash
kubesentinel attack-paths --context kind-local
```

Builds a graph from the same data `scan` already collects, no new permissions needed, and finds
every path from the internet to a namespace's secrets, cluster-admin-equivalent access, or a node
breakout through a hostPath mount. Each path is scored `theoretical`, `possible`, `reachable`, or
`high_confidence` depending on how direct the chain is and whether the entry workload already has
a real open finding, a known way in is treated as more concrete than a hypothetical one.

### Scheduled audits and security debt

```bash
kubesentinel audit --context kind-local
```

Scans, saves the result as a numbered audit snapshot, and compares it against the cluster's
previous audit (or the baseline, for the first one): findings by severity, what's new or resolved,
drift events, how the attack path count moved, and a security debt breakdown, how long each open
finding has been sitting there and in how many past scans it has shown up, read straight off a
finding's own id rather than tracked separately.

### Reports

```bash
kubesentinel report --format html --output report.html
kubesentinel report --format sarif --output results.sarif
```

SARIF output works with GitHub's Security tab and Azure DevOps code-scanning natively, no custom
upload code needed on KubeSentinel's side, just wire `github/codeql-action/upload-sarif` (or your
platform's equivalent) into a CI job that runs `kubesentinel report --format sarif`. SARIF was
designed for a source file and a line number, a live cluster resource is neither, results carry a
logical location (the resource's own kind and name) instead, still valid, still listed as an
alert, just without an inline file annotation.

### Filing tickets

```bash
kubesentinel ticket --to github --repo owner/name --min-risk high
kubesentinel ticket --to jira --min-risk critical
```

Scans, filters findings at or above `--min-risk` (default `high`), and files each one as an issue
or work item. A finding already filed against the same tracker on an earlier run is skipped, not
refiled, tracked locally by the finding's own deterministic id, so this is safe to run on a
schedule. `--dry-run` shows what would be filed without filing anything, and `--limit` caps how
many go out in one run.

`--to github` shells out to the `gh` CLI and reuses whatever `gh auth login` session is already
active, no separate credential needed. `--to jira`, `--to servicenow`, and `--to azuredevops` talk
to each system's documented REST API directly and read their credentials from environment
variables, none of the three were verified against a live instance, no credentials were available
to test against one, see `docs/roadmap.md`:

| Tracker | Environment variables |
| --- | --- |
| Jira | `KUBESENTINEL_JIRA_URL`, `KUBESENTINEL_JIRA_EMAIL`, `KUBESENTINEL_JIRA_API_TOKEN`, `KUBESENTINEL_JIRA_PROJECT` |
| ServiceNow | `KUBESENTINEL_SERVICENOW_INSTANCE`, `KUBESENTINEL_SERVICENOW_USERNAME`, `KUBESENTINEL_SERVICENOW_PASSWORD` |
| Azure DevOps | `KUBESENTINEL_AZDO_ORG`, `KUBESENTINEL_AZDO_PROJECT`, `KUBESENTINEL_AZDO_PAT` |

If the finding's resource is managed by ArgoCD or Flux, the filed ticket says so and points at
fixing it in the source repository rather than editing the live cluster, a direct edit would just
drift and get reverted on the next sync anyway.

### GitOps management

```bash
kubesentinel gitops --context kind-local
```

Reads the tracking labels ArgoCD and Flux already stamp onto everything they manage
(`argocd.argoproj.io/instance`, `kustomize.toolkit.fluxcd.io/name`, and `helm.toolkit.fluxcd.io/name`
as a fallback for a bare Flux HelmRelease with pruning or drift detection turned on) off the same
collected data `scan` uses, no new permissions needed, and shows which workloads are GitOps-managed
and which would need a direct, hand-applied fix.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

## Security principles

KubeSentinel follows least privilege by default. It is read-only against the Kubernetes API,
never collects secret values, sends no telemetry, and requires no external service to function.
Everything it needs can run entirely inside your own environment.

`--with-vulnerabilities` is the one exception worth calling out plainly: it needs to pull image
data from your container registry, which is a different trust boundary than the Kubernetes API
and isn't covered by any RBAC permission. A private registry Trivy can't authenticate to will
just fail that one image and get logged as a warning, it won't stop the rest of the scan.

## License

Apache License 2.0. See `LICENSE`.
