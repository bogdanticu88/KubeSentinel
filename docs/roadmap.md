# Roadmap

KubeSentinel is being built in phases, each one a working increment rather than a
speculative design. This file tracks where the project actually is, not where it
will eventually end up.

## Phase 1: Foundation (in progress)

- [x] Repository structure, packaging, and tooling (ruff, mypy, pytest)
- [x] Read-only Kubernetes collector: workloads, RBAC, networking, namespaces
- [x] Normalized finding and resource data model
- [x] Data-defined misconfiguration rule engine, 19 rules across workloads,
      RBAC, and networking
- [x] Dimensional, explainable security scoring
- [x] `kubesentinel scan` command
- [ ] Verified end to end against a real cluster (kind or k3d), not just fixtures

## Phase 2: Security analysis

- [ ] Secrets-handling rules (mounted-but-unused, over-shared secrets)
- [ ] Cluster-configuration rules (API server flags, admission control, where
      the API allows reading them)
- [ ] Vulnerability scanner adapter (Trivy first), normalized into the same
      finding model as the misconfiguration rules
- [ ] Correlate vulnerability findings with exposure and RBAC context rather
      than reporting CVEs in isolation

## Phase 3: Baseline and drift

- [ ] Baseline definition and storage (generated, hand-authored, or imported)
- [ ] Snapshot storage, event-sourced: one full snapshot plus an append-only
      drift-event log rather than a full copy per point in time
- [ ] Severity-weighted structural diff engine, baseline vs. current state
- [ ] `kubesentinel drift` and `kubesentinel baseline`

## Phase 4: Auditing

- [ ] Scheduled audits compared against the previous run
- [ ] Security debt tracking (age, recurrence, ownership)
- [ ] HTML and SARIF report output
- [ ] `kubesentinel audit` and `kubesentinel report`

## Phase 5: Attack graph

- [ ] In-house relationship graph over identity, workloads, network reachability,
      and exposure, informed by RBAC escalation primitives (`bind`, `escalate`,
      `impersonate`, hostPath/privileged pod creation) as first-class edges
- [ ] Path classification: theoretical, possible, reachable, high-confidence
- [ ] `kubesentinel attack-paths`

## Phase 6: Web UI

- [ ] Dashboard, findings explorer, drift view, audit history, attack path graph

## Phase 7: Integrations

- [ ] GitHub, Azure DevOps, Jira, ServiceNow, ArgoCD, Flux

AI is not on this roadmap. If it shows up later, it will be an optional layer
that reads KubeSentinel's evidence over something like MCP, not a dependency of
any engine above.
