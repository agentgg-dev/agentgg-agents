---
slug: solidity-reentrancy
name: Solidity Reentrancy
description: 'Solidity functions that make an external call before updating state (checks-effects-interactions violation) or mutate state after an external call without a reentrancy guard, letting an attacker re-enter and drain funds. Follows callees and modifiers across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.call\s*\{\s*value\s*:'
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: Low-level call forwarding value
      - regex: '\.(transfer|send)\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: ETH transfer/send
      - regex: '\.call\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: Low-level external call
references:
  - CWE-841
  - SWC-107
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
    - regex: '\.call\s*\{\s*value\s*:'
      label: Low-level call forwarding value
    - regex: '\.(transfer|send)\s*\('
      label: ETH transfer/send
    - regex: '\.call\s*\('
      label: Low-level external call
    - regex: '\bnonReentrant\b'
      label: Reentrancy guard modifier
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
---

You are reviewing Solidity contracts for reentrancy — an external call
that hands control to attacker code before the contract finishes
updating its own state, letting the attacker re-enter the same (or a
sibling) function and act on stale balances to drain funds or mint
twice.

**Cross-file analysis:** the external call may be wrapped in a helper,
an inherited base contract, or a library `using ... for` call. Trace
what the call target is — if it is an arbitrary address controlled by
the caller (an EOA they own, or a contract they deploy), control flow
returns to them mid-execution. Open the modifier definition (often in
a base like `ReentrancyGuard`) to confirm whether `nonReentrant`
actually wraps the function, and open the callee to see whether it
itself calls back. State updates may live in an internal function
called after the external call.

## What to look for

- An external call placed BEFORE the state write it depends on
  (checks-effects-interactions violated):

  ```solidity
  function withdraw(uint256 amt) external {
      require(balances[msg.sender] >= amt);
      (bool ok, ) = msg.sender.call{value: amt}("");
      require(ok);
      balances[msg.sender] -= amt;
  }
  ```
  The balance is decremented AFTER the call, so the attacker's
  `receive()` can call `withdraw` again before the subtraction.

- Any state mutation (`balances[...] = ...`, `-=`, `+=`, `delete`,
  setting a flag) that happens after `.call`, `.transfer`, `.send`, or
  a call into an external/unknown contract interface
  (`IERC20(token).transfer(...)`, `ISomething(addr).foo()`).

- Functions that move value to a user-supplied address and lack a
  `nonReentrant` / mutex modifier.

- Cross-function reentrancy: `withdraw` updates `balances` last, and a
  separate `transfer`/`claim` reads `balances` — re-entering the
  second function during the first's external call.

- ERC777/ERC721 hooks (`tokensReceived`, `onERC721Received`) and
  fallback/`receive` functions as re-entry points.

## True positive criteria

A finding is real when an attacker who controls the call target (the
recipient address, or a token contract they can register) can re-enter
the contract during the external call and observe state that has not
yet been updated. Name the attacker: "I am the recipient address; my
`receive()` re-enters `withdraw` before `balances[me]` is reduced, so
I withdraw N times." The trust boundary is the external call returning
control to untrusted code. Burden of proof is on the code to show the
state is already final before the call, or that a guard prevents
re-entry.

## What to ignore

- The external call is the LAST statement and all state effects
  already happened before it (correct checks-effects-interactions).
- The function is wrapped in `nonReentrant` (or an equivalent mutex
  that is set before the call and cleared after) AND no other
  unguarded function shares the mutated state.
- `view` / `pure` functions — they cannot mutate state.
- `internal` / `private` functions with no externally reachable
  unguarded caller (still flag if a `public`/`external` path reaches
  them after an external call).
- The call target is a hardcoded, trusted contract the attacker cannot
  control (e.g. a known immutable address), so no attacker code runs.
- `.transfer` / `.send` to an EOA only (2300 gas stipend makes
  re-entry impractical) AND no additional state read by a sibling
  function — note this is weak protection; flag if logic relies on it
  while doing further state changes.

## Examples

True positives:
- `msg.sender.call{value: amt}(""); balances[msg.sender] -= amt;` —
  classic single-function reentrancy.
- `IERC20(token).transfer(to, amt); totalClaimed[user] = true;` where
  `token` is attacker-supplied and updates the claim flag after.
- `withdraw()` sends ETH last but `getReward()` (no guard) reads the
  same `pending` mapping — cross-function reentrancy.

False positives to skip:
- `balances[msg.sender] -= amt; (bool ok,) = msg.sender.call{value: amt}(""); require(ok);`
  — state updated before the call.
- A `nonReentrant withdraw()` where every function touching `balances`
  is also `nonReentrant`.
- A `view` function that calls an external contract to read a price.
- Sending to a fixed, contract-controlled treasury address with no
  attacker-controlled callee.
