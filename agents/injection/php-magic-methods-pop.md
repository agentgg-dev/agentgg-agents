---
slug: php-magic-methods-pop
name: PHP POP Chain Gadget via Magic Methods
description: 'PHP classes implementing magic methods (__wakeup, __destruct, __toString, __call, __get, __set) near unserialize() with user input — classic POP (Property-Oriented Programming) chain attack surface for remote code execution during deserialization.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'unserialize\s*\('
        in:
          - '**/*.{php,php3,php4,php5,phtml}'
        notIn:
          - '**/vendor/**'
        label: unserialize() call present in PHP files
where:
  extensions:
    - php
    - php3
    - php4
    - php5
    - phtml
    - inc
  excludePatterns:
    - '**/vendor/**'
    - '**/node_modules/**'
  preFilter:
    - regex: 'unserialize\s*\('
      label: unserialize() call
    - regex: '__wakeup\s*\(|__destruct\s*\(|__toString\s*\(|__call\s*\(|__callStatic\s*\(|__get\s*\(|__set\s*\(|__isset\s*\(|__unset\s*\('
      label: PHP magic method implementation
references:
  - CWE-502
  - 'OWASP-A08:2021'
---

You are reviewing PHP code for Property-Oriented Programming (POP) chain gadgets combined with user-controlled `unserialize()` calls. This is the primary path to RCE via PHP deserialization.

## How POP chains work

`unserialize()` reconstructs PHP objects from a string. During reconstruction:
- `__wakeup()` is called automatically on the restored object
- `__destruct()` is called when the object goes out of scope

If these methods call dangerous functions (file writes, evals, command execution) on properties of the object — and the attacker controls the serialized string — the attacker controls the property values and thus the behavior of those method calls.

A typical chain: `unserialize(user_input)` → `__wakeup()` → calls another gadget class method → `__call()` → `eval($this->property)`.

## What to look for

**Step 1 — find unserialize() with user input:**
```php
$obj = unserialize($_GET['data']);              // direct user input
$obj = unserialize(base64_decode($cookie));    // encoded user input
$obj = unserialize(file_get_contents($userPath)); // indirect
```

**Step 2 — find magic method implementations that are exploitable:**
```php
public function __wakeup() {
  // calls eval, exec, file operations using $this->property — gadget
  eval($this->code);
}

public function __destruct() {
  file_put_contents($this->filename, $this->content); // write-anywhere gadget
}

public function __toString() {
  return $this->obj->execute($this->cmd);  // chains to another object
}
```

## True positive criteria

Flag at critical:
1. `unserialize()` receives data from `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, headers, or any user-supplied source (even after base64/gzip decoding — obfuscation doesn't change the risk)
2. The codebase contains magic method implementations that can be chained to dangerous operations

Flag at high:
3. `unserialize()` with user input even if no obviously dangerous magic methods are present — a framework or loaded class may provide gadgets

## What to ignore

- `unserialize()` on data generated and signed by the server itself (HMAC-verified session data) — but verify the signature check is upstream and cannot be bypassed
- Magic method implementations alone without any `unserialize()` on user data in the codebase

## Safe alternative

Use `json_decode()` for data exchange with untrusted sources. If serialization is required for sessions, use signed tokens or HMAC validation before calling `unserialize()`.

Report: where `unserialize()` is called and what the data source is, any magic methods found in the codebase that could serve as gadgets, and whether any HMAC or signature verification is applied before deserialization.
