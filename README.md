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

Early development. The current milestone is a working `kubesentinel scan` command: connect to a
cluster, collect security-relevant resources, run the misconfiguration rule set against them, and
print an explainable security score with the top risks. Drift detection, baselines, historical
scoring, and attack path analysis come in later phases; see `docs/roadmap.md`.

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

## License

Apache License 2.0. See `LICENSE`.
