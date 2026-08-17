---
slug: solidity-access-control
name: Solidity Access Control
description: 'Solidity state-changing public/external functions missing an owner/role check, tx.origin used for authorization, and unprotected selfdestruct, delegatecall, owner setters, or upgradeable initializers, letting an attacker take over the contract. Follows modifiers and base contracts across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\btx\.origin\b'
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: tx.origin used in logic
      - regex: '\bselfdestruct\s*\(|\bsuicide\s*\('
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: selfdestruct present
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
        label: delegatecall present
      - regex: '\bfunction\b[^;{]*\b(public|external)\b'
        in:
          - '**/*.sol'
        notIn:
          - '**/node_modules/**'
          - '**/lib/**'
          - '**/.deps/**'
          - '**/test/**'
          - '**/tests/**'
          - '**/*.t.sol'
        label: public/external function
references:
  - CWE-284
  - SWC-105
  - SWC-115
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
    - regex: '\btx\.origin\b'
      label: tx.origin used in logic
    - regex: '\bselfdestruct\s*\(|\bsuicide\s*\('
      label: selfdestruct present
    - regex: '\.delegatecall\s*\('
      label: delegatecall present
    - regex: '\bfunction\s+initialize\b'
      label: Upgradeable initializer
    - regex: '\bfunction\b[^;{]*\b(public|external)\b'
      label: public/external function
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
---

You are reviewing Solidity contracts for missing or broken access
control — a privileged, state-changing function that anyone can call,
letting an attacker change ownership, drain funds, brick the contract,
or hijack its logic.

**Cross-file analysis:** authorization usually lives in a modifier
(`onlyOwner`, `onlyRole`, `whenNotPaused`) defined in a base contract
or imported library (OpenZeppelin `Ownable`, `AccessControl`). A
function with no inline `require` may still be protected by a modifier
declared elsewhere — open the modifier source to confirm it actually
checks `msg.sender`. Conversely, a custom modifier may look protective
but check the wrong thing (e.g. `tx.origin`, or a variable an attacker
can set). For upgradeable contracts, open the base to see whether
`initialize` carries an `initializer` modifier and an owner-setting
check.

## What to look for

- `public` / `external` functions that mutate state (assign storage,
  transfer value, change config) with NO modifier and NO
  `require(msg.sender == owner / hasRole(...))`:

  ```solidity
  function setOwner(address a) external { owner = a; }
  ```

- `tx.origin` used for authorization (phishable — a malicious contract
  the owner calls can forward the call):

  ```solidity
  require(tx.origin == owner);
  ```

- Unprotected `selfdestruct` / `suicide`:

  ```solidity
  function kill() public { selfdestruct(payable(msg.sender)); }
  ```

- Unprotected `delegatecall` to a caller-supplied target (attacker
  runs arbitrary code in this contract's storage context):

  ```solidity
  function exec(address impl, bytes calldata d) external {
      impl.delegatecall(d);
  }
  ```

- Owner/admin setters and privileged config (`setFee`, `setMinter`,
  `withdraw`, `pause`, `upgradeTo`, `grantRole`) lacking a guard.

- Upgradeable initializers without the `initializer` modifier or with
  no ownership assignment — anyone can call `initialize` and become
  owner ("uninitialized proxy" takeover).

## True positive criteria

A finding is real when an arbitrary external caller (not the deployer,
not a granted role) can invoke a function that changes privileged state
or value. Name the attacker: "I am any address; I call `setOwner(me)`
and now own the contract", or "I front-run `initialize` and set myself
as admin." The trust boundary is the public/external ABI — anyone can
call it. For `tx.origin`, the attacker is a contract the legitimate
owner is tricked into calling. Burden of proof is on the code to show a
correct `msg.sender`/role check guards the function.

## What to ignore

- The function carries a real modifier (`onlyOwner`, `onlyRole`,
  `onlyAdmin`) whose definition genuinely checks `msg.sender` against
  owner/role state the attacker cannot control.
- An inline `require(msg.sender == owner)` (or `hasRole`,
  `_checkRole`, `_checkOwner`) at the top of the function.
- `view` / `pure` functions and getters — no state change.
- `internal` / `private` functions with no unprotected external caller.
- Functions intentionally open by design (e.g. `deposit`, `mint` in a
  permissionless protocol) that only affect the caller's own funds and
  cannot escalate privilege or touch others' balances.
- `selfdestruct` / `delegatecall` reachable only through an
  owner-guarded path.
- `tx.origin` used purely for logging/analytics, not authorization.
- An `initialize` correctly guarded by `initializer` /
  `reinitializer` that assigns ownership.

## Examples

True positives:
- `function setOwner(address a) external { owner = a; }` — no guard,
  any caller takes ownership.
- `require(tx.origin == owner)` gating a `transfer` — phishable.
- `function kill() public { selfdestruct(payable(msg.sender)); }` —
  anyone can destroy the contract.
- `function initialize(address admin) public { owner = admin; }` with
  no `initializer` modifier — front-runnable proxy takeover.
- `function execute(address t, bytes d) external { t.delegatecall(d); }`
  — arbitrary code in this contract's storage.

False positives to skip:
- `function setFee(uint f) external onlyOwner { fee = f; }` where
  `onlyOwner` checks `msg.sender == owner`.
- `function deposit() external payable { balances[msg.sender] += msg.value; }`
  — permissionless, only affects the caller.
- A public getter `function balanceOf(address a) external view`.
- `function initialize(...) public initializer { __Ownable_init(); }`.
