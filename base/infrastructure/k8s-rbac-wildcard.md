---
slug: k8s-rbac-wildcard
name: Kubernetes RBAC Wildcard Over-Permission
description: 'Role/ClusterRole rules with wildcard verbs/resources/apiGroups, broad access to secrets, or bindings to cluster-admin / overly broad subjects (system:authenticated, all service accounts). Correlates a Role with its RoleBinding across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)'
        in:
          - '**/*.yaml'
          - '**/*.yml'
        label: rbac-kind
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
    - regex: 'kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)'
      label: rbac-kind
    - regex: 'verbs:\s*\[[^\]]*"\*"'
      label: wildcard-verbs
    - regex: 'resources:\s*\[[^\]]*"\*"'
      label: wildcard-resources
    - regex: 'apiGroups:\s*\[[^\]]*"\*"'
      label: wildcard-apigroups
    - regex: '-\s*"?\*"?\s*$'
      label: bare-wildcard-item
    - regex: '(secrets|cluster-admin)'
      label: sensitive-target
    - regex: 'system:(authenticated|unauthenticated|serviceaccounts)'
      label: broad-subject
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-269
  - CWE-732
  - 'OWASP-A01:2021'
---

You are reviewing Kubernetes RBAC objects (Role, ClusterRole,
RoleBinding, ClusterRoleBinding) for over-permissioning. An attacker who
compromises a service account bound to an over-broad role can read every
secret, create privileged pods, modify other workloads, or escalate to
full cluster control — RBAC is the last line of defense between a
single compromised pod and the whole cluster.

## Cross-file analysis

A Role/ClusterRole grants nothing by itself — it is only dangerous when
a binding attaches it to a subject. The two halves are frequently in
separate files:
- Find the dangerous **Role/ClusterRole** (wildcard verbs/resources, or
  `secrets` with `get`/`list`/`watch`), then look for the
  **RoleBinding/ClusterRoleBinding** in the same chart/directory whose
  `roleRef.name` matches. Report the pair: "this binding grants subject
  S the permissions of this over-broad role."
- A `ClusterRoleBinding` to the built-in `cluster-admin` ClusterRole is
  a finding on its own — you do not need to find a Role definition,
  `cluster-admin` is god-mode by definition.
- **Subjects** matter: a binding to `system:authenticated`,
  `system:unauthenticated`, or
  `system:serviceaccounts` (all SAs in a namespace or cluster-wide)
  spreads the grant far beyond one workload.
- **Helm:** `roleRef.name` / subject names may be templated
  (`{{ .Release.Name }}-role`); match on the rendered convention.

## What to look for

**Wildcard rule (any verb on any resource):**
```yaml
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

**Broad access to secrets:**
```yaml
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
```

**Binding to cluster-admin:**
```yaml
kind: ClusterRoleBinding
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: my-app
```

**Overly broad subject:**
```yaml
subjects:
  - kind: Group
    name: system:authenticated
```

**Escalation-enabling verbs** on `roles`/`clusterroles`/`rolebindings`
(`create`, `bind`, `escalate`), or `create` on `pods` (lets the holder
launch a privileged pod and mount node secrets).

## True positive criteria

Flag when you can name the subject and the capability it gains. "As the
holder of service account S, because of this rule/binding I can do X":
1. A rule with `verbs: ["*"]`, `resources: ["*"]`, or
   `apiGroups: ["*"]` (the JSON-array `"*"` or a bare `- "*"` list item).
2. A rule granting `get`/`list`/`watch` on `secrets` more broadly than
   the workload needs — I can read every credential in scope.
3. A binding whose `roleRef.name` is `cluster-admin` — I am cluster
   admin.
4. A binding whose subject is `system:authenticated`,
   `system:unauthenticated`, or a `system:serviceaccounts*` group — the
   grant reaches arbitrary identities.
5. A rule with `escalate`/`bind`/`create` on RBAC objects, or `create`
   on `pods`/`deployments` — I can grant myself more, or run a
   privileged pod.

A `ClusterRole` (cluster-wide) is higher impact than a namespaced
`Role`; weight accordingly but still flag namespaced wildcards.

## What to ignore

- A narrowly scoped Role that lists specific verbs on specific named
  resources (`verbs: ["get"]`, `resources: ["configmaps"]`,
  `resourceNames: ["my-config"]`) — least privilege, not a finding.
- The built-in default ClusterRoles shipped by Kubernetes (`view`,
  `edit`, `admin`) when referenced by name; flag only `cluster-admin`
  or custom over-broad roles.
- A Role with wildcards that is never referenced by any binding in the
  repo (note it as latent, lower confidence).
- Bindings whose subject is a single, specific ServiceAccount scoped to
  the namespace that genuinely needs the access (e.g. a controller that
  must watch its own CRDs).
- Example/docs manifests under `examples/` clearly marked as samples.

## Examples

True positives:
```yaml
kind: ClusterRole
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

```yaml
kind: ClusterRoleBinding
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:authenticated
```

False positives to skip:
```yaml
kind: Role
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get", "list"]
```

```yaml
kind: RoleBinding
roleRef:
  kind: ClusterRole
  name: view
subjects:
  - kind: ServiceAccount
    name: dashboard
    namespace: monitoring
```
