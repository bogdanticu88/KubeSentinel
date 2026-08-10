# Roadmap

KubeSentinel is being built in phases, each one a working increment rather than a
speculative design. This file tracks where the project actually is, not where it
will eventually end up.

## Phase 1: Foundation (done)

- [x] Repository structure, packaging, and tooling (ruff, mypy, pytest)
- [x] Read-only Kubernetes collector: workloads, RBAC, networking, namespaces
- [x] Normalized finding and resource data model
- [x] Data-defined misconfiguration rule engine, 19 rules across workloads,
      RBAC, and networking
- [x] Dimensional, explainable security scoring
- [x] `kubesentinel scan` command
- [x] Verified end to end against a real cluster (kind), not just fixtures

## Phase 2: Security analysis (done)

- [x] Secrets-handling rules (env-based secret consumption, automount not
      disabled)
- [x] Cluster-configuration rules (kube-apiserver command-line flags, read
      from the static pod's own spec, no extra API access required)
- [x] Vulnerability scanner adapter (Trivy), normalized into the same
      finding model as the misconfiguration rules, opt-in via
      `--with-vulnerabilities`
- [x] Correlate vulnerability findings, and workload misconfiguration
      findings, with exposure and RBAC context rather than reporting them
      in isolation. Reproduces both worked risk examples from the original
      design brief exactly.
- [ ] Not yet done: dedup a Pod's findings against its owning Deployment,
      currently both get flagged separately for the same thing since they
      are genuinely separate API objects. Needs an owner-reference
      correlation pass, likely folded into the Phase 3 or Phase 5 work.

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
