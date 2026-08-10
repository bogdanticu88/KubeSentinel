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

Early development. `kubesentinel scan` works end to end: connect to a cluster, collect
security-relevant resources, run the misconfiguration rule set, optionally scan workload images
for known vulnerabilities with Trivy, and print an explainable, risk-weighted score. Risk is
adjusted from a finding's raw severity based on whether its workload is exposed and what its
ServiceAccount can do, not just reported at face value. Baselines, drift detection, historical
scoring, and the attack path graph come in later phases; see `docs/roadmap.md`.

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
