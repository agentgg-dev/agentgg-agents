---
slug: android-dynamic-broadcast-receiver
name: Android Unprotected Dynamic Broadcast Receiver
description: 'Dynamic broadcast receivers registered without a permission restriction or RECEIVER_NOT_EXPORTED flag — any app on the device can send intents to the receiver, enabling unauthorized data injection or state manipulation.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'registerReceiver\s*\('
        in:
          - '**/*.java'
          - '**/*.kt'
        notIn:
          - '**/build/**'
          - '**/test/**'
          - '**/androidTest/**'
        label: registerReceiver() call in Java/Kotlin source
where:
  extensions:
    - java
    - kt
  excludePatterns:
    - '**/build/**'
    - '**/test/**'
    - '**/androidTest/**'
    - '**/node_modules/**'
  preFilter:
    - regex: 'registerReceiver\s*\('
      label: registerReceiver() call
references:
  - CWE-925
  - CWE-200
---

You are reviewing Android Java/Kotlin code for dynamically registered broadcast receivers that lack permission protection, allowing any app to broadcast intents to them.

## The vulnerability

Dynamically registered receivers (via `registerReceiver()`) are exported to all apps on the device by default in Android versions before Android 13 (API level 33). Any app can send a broadcast to the receiver without needing a permission.

```java
// VULNERABLE: any app can send this broadcast
IntentFilter filter = new IntentFilter("com.app.MY_ACTION");
registerReceiver(myReceiver, filter);
```

An attacker can:
1. Send a crafted Intent matching the filter action
2. Inject arbitrary extras into the Intent
3. Trigger the receiver's `onReceive()` logic with attacker-controlled data

## What to check in `onReceive()`

Trace what happens with `intent.getStringExtra()`, `intent.getIntExtra()`, etc.:
- If extras are used in SQL queries — SQL injection
- If extras are used in file paths — path traversal
- If extras are used in commands or `startActivity()` — escalation
- If extras are used in WebView URL loading — open redirect or SSRF

## Protection mechanisms

**Android 13+ (API 34+):** `registerReceiver()` requires explicit flags:
```kotlin
// safe: only exported if you explicitly set RECEIVER_EXPORTED
registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)  // restricts to same app
registerReceiver(receiver, filter, permission, null)       // requires sender permission
```

**Pre-Android 13:** Must pass a permission string:
```java
// safe: requires sender to hold this permission
registerReceiver(myReceiver, filter, "com.app.MY_PERMISSION", null);
```

## True positive criteria

Flag at high:
1. `registerReceiver(receiver, filter)` with no permission argument (2-arg form) targeting API < 33
2. `registerReceiver(receiver, filter, null, null)` — explicit null permission

Flag at medium:
3. `registerReceiver()` on API 33+ without `RECEIVER_NOT_EXPORTED` — ambiguous default in some SDK versions

## What to ignore

- `registerReceiver()` with a non-null permission string — protected
- `LocalBroadcastManager.registerReceiver()` — intra-process only, not exported
- Receivers registered and immediately unregistered in the same scope (no actual exposure window if logic is safe)

Report: the action strings in the IntentFilter, what the `onReceive()` method does with Intent extras, and whether any permission protection is applied.
