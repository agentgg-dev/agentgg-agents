---
slug: k8s-pod-security-context
name: Kubernetes Pod Insecure Security Context
description: 'Workload manifests (Pod/Deployment/DaemonSet/StatefulSet/Job, incl. Helm templates) with dangerous or missing securityContext — privileged, hostPID/IPC/Network, allowPrivilegeEscalation, runAsRoot, no readOnlyRootFilesystem, caps not dropping ALL, no seccompProfile. Follows Helm values into templates.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)'
        in:
          - '**/*.yaml'
          - '**/*.yml'
        label: workload-kind
      - regex: '(privileged|hostPID|hostIPC|hostNetwork|allowPrivilegeEscalation|securityContext|capabilities)'
        in:
          - '**/*.yaml'
          - '**/*.yml'
        label: securitycontext-keys
where:
  extensions:
    - yml
    - yaml
  filePatterns:
    - '**/*.yaml'
    - '**/*.yml'
    - '**/templates/**/*.tpl'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/.terraform/**'
  preFilter:
    - semgrepRule: infrastructure/k8s-privileged
      label: Kubernetes privileged container or dangerous host access setting
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-250
  - CWE-269
  - 'OWASP-A05:2021'
---

You are reviewing Kubernetes workload manifests (Pod, Deployment,
DaemonSet, StatefulSet, Job, CronJob — including Helm templates) for
dangerous or missing `securityContext` settings. A container that runs
privileged, shares host namespaces, or can escalate privileges turns a
single in-container compromise into a node/cluster takeover: the
attacker who gets RCE in such a pod can mount the host filesystem,
access other containers, and pivot to the kubelet or other nodes.

## Cross-file analysis

The dangerous value is often a few hops away from the manifest you are
reading:
- **Helm:** the template under `templates/` may read
  `securityContext: {{ toYaml .Values.securityContext }}` or
  `privileged: {{ .Values.privileged }}`. Open the matching
  `values.yaml` to learn the effective value. A template that defaults
  to insecure values (`privileged: {{ .Values.privileged | default true }}`)
  is a finding even if no override is present.
- **Pod vs container scope:** `securityContext` exists at BOTH the pod
  level (`spec.securityContext`) and the container level
  (`spec.containers[].securityContext`). Container-level settings
  override pod-level. A safe pod-level default can be silently undone by
  a permissive container-level block — read both.
- **Workload kinds wrap a pod template** under `spec.template.spec`. The
  container array lives there for Deployment/DaemonSet/StatefulSet/Job;
  CronJob nests one level deeper under `spec.jobTemplate.spec.template`.

## What to look for

**Privileged container (full host access):**
```yaml
securityContext:
  privileged: true
```

**Host namespace sharing:**
```yaml
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
```

**Privilege escalation allowed (or not explicitly denied):**
```yaml
securityContext:
  allowPrivilegeEscalation: true
```

**Running as root:**
```yaml
securityContext:
  runAsUser: 0
```
or no `runAsNonRoot: true` anywhere in the pod/container context.

**Dangerous capabilities / not dropping ALL:**
```yaml
securityContext:
  capabilities:
    add: ["SYS_ADMIN", "NET_ADMIN"]
```

**Missing hardening (writable root fs, no seccomp):** no
`readOnlyRootFilesystem: true`, no
`seccompProfile: { type: RuntimeDefault }`.

**Auto-mounted token on a sensitive workload:**
```yaml
spec:
  automountServiceAccountToken: true
```

## True positive criteria

Flag when, for a real workload kind, you can name the attacker
capability the setting grants. Be able to say "I am an attacker with
code execution in this container, and because of X I can do Y to the
host/cluster":
1. `privileged: true` — I can access all host devices and the host
   filesystem; effectively root on the node.
2. `hostPID`/`hostIPC`/`hostNetwork: true` — I can see/signal host
   processes, read host IPC, or sniff/spoof host network traffic.
3. `allowPrivilegeEscalation: true` (or absent with no other guard) —
   setuid binaries let me gain more privileges than the parent.
4. `runAsUser: 0` or no `runAsNonRoot: true` — I run as root inside the
   container, amplifying any escape.
5. `capabilities.add` includes `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`,
   `SYS_MODULE`, or the spec does not `drop: ["ALL"]`.
6. Missing `readOnlyRootFilesystem: true` or missing `seccompProfile`
   on a workload handling untrusted input.

Burden of proof is on the manifest to show it is hardened.

## What to ignore

- A securityContext that is already hardened: `runAsNonRoot: true`,
  `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
  `capabilities: { drop: ["ALL"] }`, and a `seccompProfile`. Do not
  flag a missing field when an equivalent guard is present.
- Resources that are not workloads (Service, ConfigMap, Ingress,
  NetworkPolicy) — those have no pod securityContext.
- Infrastructure DaemonSets that genuinely require host access (CNI
  plugins, node-exporter, storage drivers) when the elevated setting is
  documented and scoped — note them but treat as lower confidence.
- Helm templates that are clearly examples/docs (under `examples/`,
  marked as samples) and not rendered into a real release.
- Capability `add` of harmless caps (e.g. `NET_BIND_SERVICE` to bind
  port 80) when `drop: ["ALL"]` is also present.

## Examples

True positives:
```yaml
kind: Deployment
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: app
          securityContext:
            privileged: true
```

```yaml
kind: DaemonSet
spec:
  template:
    spec:
      containers:
        - name: agent
          securityContext:
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN"]
```

False positives to skip:
```yaml
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```
