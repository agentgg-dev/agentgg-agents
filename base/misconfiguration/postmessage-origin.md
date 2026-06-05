---
slug: postmessage-origin
name: postMessage Listener Without Origin Check
description: window.addEventListener('message') / window.onmessage handlers that act on event.data without validating event.origin — any iframe / opened window can send messages.
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  preFilter:
    - regex: 'postMessage\s*\(|\.onmessage\s*=|addEventListener\([^)]*message'
      label: postMessage listener/sender
references:
  - CWE-346
  - 'OWASP-A05:2021'
---

You are reviewing client-side JavaScript for `window.addEventListener("message", ...)`
or `window.onmessage` handlers that act on the message payload
without validating `event.origin`.

## Why this matters

`postMessage` lets any window (iframes, opened popups, the parent
frame) post arbitrary data to a listening window. Without an origin
check, the listener trusts every message — an attacker who can load
your page inside an iframe (or get a user to click a popup) can
inject commands.

## What to look for

**Listener with no `event.origin` check:**
```ts
window.addEventListener("message", (event) => {
  document.body.innerHTML = event.data;
});

window.addEventListener("message", handleMsg);

iframe.onmessage = (e) => {
  console.log(e.data);
};
```

**Listener registered via shorthand:**
```ts
window.onmessage = handler;
frame.onmessage = function (e) { dispatch(e.data); };
```

**Origin check that's bypassable:**
```ts
if (event.origin.includes("example.com")) ok();
// Bypass: https://example.com.evil.com
```

## Safe pattern

```ts
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.example.com") return;
  // Now process event.data
});
```

Use `===` against the expected origin string, or against a small
allowlist:
```ts
const ALLOWED = ["https://app.example.com", "https://admin.example.com"];
if (!ALLOWED.includes(event.origin)) return;
```

## True positive criteria

Flag when ALL of the following hold:

1. A `message` event listener is registered:
   `addEventListener("message", ...)`, `onmessage = ...`.
2. The handler body does not check `event.origin` with `===` /
   `!==` against a known origin (or an allowlist) before acting on
   `event.data`.
3. The handler performs an action: writing to DOM, calling an API,
   updating state, etc.

## What to ignore

- Listeners that check `event.origin` correctly.
- Listeners that only log: `console.log(event.data)`.
- Test files.

## Examples

True positives:
```ts
// No origin check
window.addEventListener("message", (event) => {
  document.body.innerHTML = event.data;
});

// Looks like a check, but is bypassable
window.addEventListener("message", (e) => {
  if (e.origin.includes("trusted.com")) handle(e.data);
});
```

False positives to skip:
```ts
// Correct check
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.example.com") return;
  handle(event.data);
});

// Allowlist check
const ALLOWED = ["https://app.example.com"];
window.addEventListener("message", (event) => {
  if (!ALLOWED.includes(event.origin)) return;
  handle(event.data);
});
```
