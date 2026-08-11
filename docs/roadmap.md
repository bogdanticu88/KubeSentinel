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

## Phase 4: Auditing (done)

- [x] `kubesentinel audit`: a numbered, stored audit snapshot compared
      against the previous audit for that cluster, or the baseline if this
      is the first one. Findings by severity, new/resolved/drift counts,
      attack path count delta, security debt.
- [x] Security debt tracking: age and recurrence read straight off how many
      stored snapshots a finding's (deterministic) id has appeared in, no
      separate tracking table needed. Owner attribution from the original
      design was skipped, nothing in the data model reliably identifies who
      owns a resource yet.
- [x] SARIF 2.1.0 and self-contained HTML report output, `kubesentinel
      report --format html|sarif|json`. SARIF was built for source files
      with a line number, a live cluster resource is not one, results use a
      SARIF logicalLocation instead of a physicalLocation, still valid,
      still ingested by GitHub's Security tab and generic SARIF viewers,
      just without an inline file annotation.
- [x] Live-verified a real fix this surfaced: a Role with `resources: ["*"]`
      and only read verbs (`get`, `list`) was being modeled as cluster-admin
      equivalent, the same as a Role with wildcard verbs. Reading everything
      is a severe exposure on its own (still correctly flagged via the
      secrets edge) but it cannot create, modify, or delete anything, a
      meaningfully smaller risk than true cluster-admin power. Caught by
      narrowing a live Role's verbs and watching the attack-paths count not
      change when it should have, fixed, then reconfirmed the count dropped
      correctly on the next audit, including retroactively against
      already-stored historical snapshots, since attack paths are always
      recomputed from stored resources, never cached.

## Phase 5: Attack graph (done)

- [x] In-house relationship graph (NetworkX), built from data already collected,
      no new API permissions needed. Internet as the synthetic entry point,
      real Service/Ingress/Workload/ServiceAccount/Role nodes, and two
      synthetic sinks: a per-namespace secrets-access capability (actual
      Secret objects and values are never collected, so this is the
      capability to read them, not one specific secret) and a
      cluster-admin-equivalent node for RBAC escalation and wildcard grants.
- [x] Path classification: theoretical (mechanism unconfirmed, a hostPath
      mount might not point at anything exploitable), possible (needs the
      attacker to actively use a granted capability, escalate/bind/
      impersonate), reachable (every edge is a verified structural
      relationship), high_confidence (the entry workload already has an open
      critical or high finding, a known way in rather than a hypothetical
      one). Escalation is computed from the same findings the misconfiguration
      and vulnerability engines already produced, not recomputed separately.
- [x] `kubesentinel attack-paths`, terminal and JSON output.
- [x] Correctly models a real RBAC nuance: a RoleBinding referencing a
      ClusterRole only grants access within the RoleBinding's own namespace,
      only a ClusterRoleBinding actually reaches every namespace. Verified
      with a dedicated test before trusting it.
- [x] Shared the exposure-selector and RBAC-binding joins with the risk
      correlation engine (`relationships.py`) instead of duplicating them,
      correlation stops at one hop, the graph keeps going, no reason to
      compute the same facts twice.
- [x] Scoped out for now: true node-level lateral movement (which workload
      can reach another via shared node placement) needs per-pod node
      scheduling data, which the Phase 2 dedup fix deliberately stopped
      collecting. hostPath-based node breakout is still modeled as a path to
      a generic Node sink, cross-workload movement via a shared node is not.
- [x] Verified against the same kind cluster: found the payments-api example's
      two paths (Internet to cluster-admin, Internet to namespace secrets)
      exactly matching the shape of the original design brief's own worked
      example, both scored high_confidence because the workload has real
      open critical findings right now, not hypothetically.

## Phase 6: Web UI

- [ ] Dashboard, findings explorer, drift view, audit history, attack path graph

## Phase 7: Integrations (done)

- [x] `kubesentinel ticket`: files open findings, at or above `--min-risk`, into GitHub, Jira,
      ServiceNow, or Azure DevOps. A shared `Ticketer` protocol and shared title/body formatting
      live in `integrations/ticketer.py`, each system is one small adapter on top of that, not
      four independent implementations of the same formatting logic.
- [x] GitHub via the `gh` CLI, mirroring how `TrivyAdapter` shells out to `trivy`: reuses whatever
      `gh auth login` session is already active rather than asking KubeSentinel to hold its own
      GitHub credentials. The only one of the four verified against something real, `gh` was
      already authenticated in the dev environment.
- [x] Jira (REST API v2, plain-text description rather than v3's Atlassian Document Format),
      ServiceNow (Table API, POST to `/api/now/table/incident`), and Azure DevOps (Work Items API,
      JSON Patch body, personal access token auth), each built directly against its own public,
      documented API. None of the three were verified against a live instance, no credentials were
      available to test against one. Tests cover request shape and response handling with a mocked
      `requests.post`, not a live round trip, called out explicitly rather than left implicit.
- [x] A finding already filed against a given tracker is skipped on a later run rather than
      refiled, tracked in a small local `filed_tickets` table keyed on the finding's own
      deterministic id plus which tracker it went to, so `ticket` is safe to run on a schedule.
- [x] `kubesentinel gitops`: reads the tracking labels ArgoCD (`argocd.argoproj.io/instance`) and
      Flux (`kustomize.toolkit.fluxcd.io/name`, `helm.toolkit.fluxcd.io/name` as a fallback for a
      HelmRelease with pruning or drift detection on) already stamp onto everything they manage,
      off data `scan` already collects, no new permissions needed. When `ticket` files a finding
      for a GitOps-managed resource, the ticket says so and points at the source repository
      instead of a direct cluster edit, which would just drift and get reverted on the next sync.
- [x] Verified against the same kind cluster: `kubesentinel gitops` correctly showed all nine
      collected workloads as unmanaged before any labels were present, then a live
      `kubectl label` adding `argocd.argoproj.io/instance` to the payments-api Deployment showed
      up correctly on the next run, both the summary count and which application owns it.
      `kubesentinel ticket --to github --dry-run` was run against the same live cluster and
      correctly filtered to findings at or above the risk threshold, in the right order, with no
      network call made. Filing a real GitHub issue was deliberately not exercised in this
      session, kubesentinel itself has no GitHub remote yet and there was no designated repo to
      file a test issue into.

AI is not on this roadmap. If it shows up later, it will be an optional layer
that reads KubeSentinel's evidence over something like MCP, not a dependency of
any engine above.
