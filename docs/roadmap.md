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
- [x] Stop collecting a Pod owned by a ReplicaSet, StatefulSet, DaemonSet,
      or Job, and a Job owned by a CronJob, they carried the exact same pod
      template as their controller and every finding showed up once per
      running replica on top of once for the controller. Static pods like
      kube-apiserver are owned by the Node, not a controller, and are
      unaffected.

## Phase 3: Baseline and drift (done)

- [x] Snapshot storage. Local SQLite, one file under `~/.kubesentinel/`, not
      Postgres, deliberate deviation from the original tech stack, this is a
      CLI one operator runs from a laptop, not a server with concurrent
      writers, so a local file fits better than standing up a database.
- [x] Baseline is the reference snapshot for its cluster, `kubesentinel
      baseline create` (auto-generated from a live scan) or `baseline show`.
      Hand-authored and imported baselines from the original design are not
      built, auto-generated from a snapshot covers the common case and a
      full policy-authoring format would mostly duplicate what the
      misconfiguration rules already check.
- [x] Full snapshots per capture rather than an event-sourced replay log,
      revised from the original plan once the numbers were actually looked
      at: a local CLI doing periodic manual snapshots was never going to hit
      the storage volume that made replay worth its complexity.
- [x] Structural diff engine comparing the same normalized `data` every rule
      already reads, so every field difference found is inherently something
      a rule could care about, with a per-field severity table for how much a
      given change matters (ServiceAccount or hostNetwork changing outranks
      a label). Finding-level new/resolved plus score delta, matching the
      original design brief's worked example exactly.
- [x] `kubesentinel drift` (fresh scan vs. baseline or `--since 7d/24h/30m`)
      and `kubesentinel compare <id> <id>` (two stored snapshots, fully
      offline, no cluster needed).
- [x] Verified against the same kind cluster: patched a live Deployment's
      ServiceAccount and privileged flag, confirmed drift caught both, the
      score moved the right direction, and compare against stored snapshot
      ids reproduced the identical report with no cluster connection at all.

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
