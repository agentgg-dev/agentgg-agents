---
slug: sandbox-runtime-script
name: Sandbox / VM Runtime Executing User Code
description: 'vm.runInNewContext, vm.runInThisContext, vm2, isolated-vm, ses-shim, py-sandbox, Lua sandbox, or similar runtimes executing caller-supplied code — most are not true sandboxes and can be escaped. Walker mode follows sandbox-setup helpers and exposed globals.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: vm\.(runInNewContext|runInThisContext|runInContext|Script)\s*\(|new\s+vm\.Script\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Node vm module call
      - regex: 'new\s+VM\s*\(|from\s+[''"]vm2[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'vm2 (deprecated, multiple sandbox escapes)'
      - regex: isolated-vm|new\s+ivm\.Isolate
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: isolated-vm Isolate
      - regex: new\s+Compartment\s*\(|\bses-shim\b
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: SES Compartment
      - regex: new\s+Function\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: new Function() runtime code construction
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: vm\.(runInNewContext|runInThisContext|runInContext|Script)\s*\(|new\s+vm\.Script\s*\(
      label: Node vm module call
    - regex: 'new\s+VM\s*\(|from\s+[''"]vm2[''"]'
      label: 'vm2 (deprecated, multiple sandbox escapes)'
    - regex: isolated-vm|new\s+ivm\.Isolate
      label: isolated-vm Isolate
    - regex: new\s+Compartment\s*\(|\bses-shim\b
      label: SES Compartment
    - regex: new\s+Function\s*\(
      label: new Function() runtime code construction
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-94
  - CWE-913
  - 'OWASP-A04:2021'
---

You are reviewing source code for code-evaluation runtimes that
execute caller-supplied JavaScript / Python / Lua scripts.

**Walker mode advantage:** sandboxing posture depends on what's
exposed to the sandbox context — `fs`, `child_process`, fetch, host
references — and on memory/time budgets. When the candidate calls
`runInNewContext(code, sandbox)`, open the `sandbox` object's
construction site and enumerate what it grants. Also follow helper
calls like `runUserScript(code)` to see whether the helper sets a
real budget. Many
"sandboxes" advertise isolation but are routinely escaped — Node's
built-in `vm` module is explicitly not a security boundary, and
`vm2` has had multiple sandbox escapes leading to its
deprecation.

## What to look for

**Node.js `vm` module:**
```ts
import vm from "node:vm";
const result = vm.runInNewContext(userCode, sandbox);
vm.runInThisContext(snippet);
new vm.Script(code).runInNewContext({});
```
The Node docs explicitly say `vm` is not a security mechanism.

**`vm2` (deprecated, multiple known escapes):**
```ts
import { VM } from "vm2";
const vm = new VM();
vm.run(userScript);
```
The maintainer deprecated vm2 after sandbox escapes; if you see
it, recommend migration.

**`isolated-vm` (the safer alternative):**
```ts
import ivm from "isolated-vm";
const isolate = new ivm.Isolate({ memoryLimit: 128 });
```
Generally regarded as the most robust JS sandbox, but still requires
careful API surface control.

**SES (Secure ECMAScript) / Compartment:**
```ts
import "ses";
lockdown();
const compartment = new Compartment({});
compartment.evaluate(userCode);
```
Safer than `vm`, but the host objects exposed to the compartment
matter.

**Python sandboxes:**
```python
exec(user_code, restricted_globals)   # restricted_globals is NOT a sandbox
```

**Lua sandboxes:**
```lua
local fn = load(user_code, "user", "t", sandbox)   -- sandbox is a table
```

## Required mitigations (review)

If a runtime is used, verify:
1. **Time budget:** an enforced wall-clock or CPU budget.
2. **Memory budget:** `isolated-vm` `memoryLimit`, `--max-old-space-size`.
3. **No host references:** the sandbox doesn't have access to `fs`,
   `child_process`, `Function`, `eval`, network APIs, or other host
   capabilities unless required by the use case.
4. **Network isolation:** the process itself can't reach internal
   services (egress rules, no metadata service access).

## True positive criteria

Flag when:
1. `vm.runInNewContext`, `vm.runInThisContext`, `vm.Script`,
   `new VM()` (vm2), `new Function()`, `eval()`, or equivalent code
   evaluator is called with caller-controlled input.
2. The runtime is used WITHOUT memory / time / API-surface limits.

## What to ignore

- Code-evaluation runtimes used with hardcoded, controlled scripts
  (not caller input).
- Test files.
- Build-tooling that evaluates trusted config files.

## Examples

True positives:
```ts
// vm with no limits
import vm from "node:vm";
const result = vm.runInNewContext(req.body.code, {});

// vm2 with caller-supplied script
import { VM } from "vm2";
new VM().run(userInput);

// new Function from request
const fn = new Function(req.body.expression);
fn();
```

False positives to skip:
```ts
// isolated-vm with memory + time budget
import ivm from "isolated-vm";
const isolate = new ivm.Isolate({ memoryLimit: 64 });
const ctx = await isolate.createContext();
const script = await isolate.compileScript(userCode);
const result = await script.run(ctx, { timeout: 500 });

// Hardcoded eval
const x = eval("1 + 1");
```
