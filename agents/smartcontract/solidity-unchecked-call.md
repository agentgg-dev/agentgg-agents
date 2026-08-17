---
slug: solidity-unchecked-call
name: Solidity Unchecked Low-Level Call
description: 'Solidity low-level call, delegatecall, or send whose boolean success return is ignored rather than checked with require/if, causing silent failures where the contract assumes a transfer or call succeeded when it reverted. Follows return-value handling across helpers.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.call\s*(\{[^}]*\})?\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: Low-level call
      - regex: '\.delegatecall\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: delegatecall
      - regex: '\.send\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: send returning bool
references:
  - CWE-252
  - SWC-104
where:
  extensions:
    - sol
  excludePatterns:
    - '**/node_modules/**'
    - '**/lib/**'
    - '**/.deps/**'
    - '**/test/**'
    - '**/tests/**'
    - '**/*.t.sol'
  preFilter:
    - regex: '\.call\s*(\{[^}]*\})?\s*\('
      label: Low-level call
    - regex: '\.delegatecall\s*\('
      label: delegatecall
    - regex: '\.send\s*\('
      label: send returning bool
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
---

You are reviewing Solidity contracts for unchecked low-level call
return values — a `.call`, `.delegatecall`, or `.send` whose boolean
success flag is discarded, so the contract proceeds as if the call
succeeded even when it reverted. An attacker (or a failing callee) can
make the call silently fail while the contract updates state, marks a
payment as sent, or moves on, leaving funds stuck or accounting wrong.

**Cross-file analysis:** the call result may be returned from a helper
(`function _pay(...) internal returns (bool)`) whose caller then
ignores the returned bool. Trace whether the success value is actually
consumed somewhere up the chain. A wrapper that returns `success` is
fine only if every caller checks it. Distinguish low-level calls
(return `bool`, never auto-revert) from `.transfer` and external
interface calls like `IERC20(t).transfer(...)` (which DO revert on
failure — different class).

## What to look for

- A low-level `.call` / `.delegatecall` / `.send` used as a statement
  with the bool dropped:

  ```solidity
  msg.sender.call{value: amt}("");
  payable(to).send(amt);
  target.delegatecall(data);
  ```

- The bool captured into a variable that is then never read:

  ```solidity
  (bool ok, ) = addr.call{value: v}("");
  balances[to] -= v;
  ```
  `ok` is assigned but never checked before the state change.

- Tuple destructuring that ignores success: `(, bytes memory r) = a.call(d);`

- `.send` (returns bool, does NOT revert) used to pay out without an
  `if (!sent) revert` / `require(sent)`.

- Raw `.call` used specifically to forward ETH where the result is not
  gated before subsequent effects.

## True positive criteria

A finding is real when a low-level call's success bool is not checked
with `require`, `assert`, an `if` that reverts, or by propagating it to
a caller that checks it — AND the contract performs a state change or
returns success on the assumption the call worked. Name the impact:
"I am the recipient contract; my fallback reverts, so `send` returns
false, but the contract still marks my withdrawal complete / decrements
my debt." The trust boundary is the external callee, which can fail or
deliberately revert. Burden of proof is on the code to show the bool is
checked or that failure is intentionally tolerated and safe.

## What to ignore

- The return value IS checked: `require(ok, "fail")`,
  `if (!ok) revert(...)`, `assert(ok)`, or `(bool ok, ) = ...; if (!ok) { ... }`.
- The bool is returned to a caller that checks it (verify the caller).
- High-level external calls that auto-revert on failure:
  `IERC20(t).transfer(...)`, `token.transferFrom(...)`,
  `payable(to).transfer(amt)` (note: `.transfer`, not `.send`) — these
  revert by default, so an ignored "return" is not this bug.
- `delegatecall` / `call` whose returned `bytes` are explicitly
  bubbled up with assembly `revert` on failure (proxy patterns that
  forward revert data).
- `view` / `pure` and `staticcall` read-only probes where failure is
  intentionally ignored (e.g. feature-detection), and the contract
  does not act on a false assumption of success.
- Cases where failure genuinely has no security/accounting consequence
  and is documented as best-effort.

## Examples

True positives:
- `payable(to).send(amount);` with no `require` on the result.
- `(bool ok, ) = msg.sender.call{value: refund}(""); refunded[msg.sender] = true;`
  — state set regardless of `ok`.
- `to.call{value: v}("");` as a bare statement to pay out.
- `impl.delegatecall(data);` ignoring success in a non-proxy setter.

False positives to skip:
- `(bool ok, ) = to.call{value: v}(""); require(ok, "transfer failed");`
- `require(payable(to).send(amt), "send failed");`
- `IERC20(token).transfer(to, amt);` — reverts on failure by design.
- `payable(to).transfer(amt);` — `.transfer` auto-reverts.
- A proxy `fallback` that delegatecalls and bubbles up revert data via
  assembly.
