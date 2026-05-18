---
slug: event-handler-mismatch
name: Event Handler Name Contradicts Event Name
description: Event consumer / webhook dispatcher where the handler function name doesn't match the event type — copy-paste bug that silently calls the wrong handler.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/event-consumer*.{ts,js,mjs}"
  - "**/handler*.{ts,js,mjs}"
  - "**/subscriber*.{ts,js,mjs}"
  - "**/consumer*.{ts,js,mjs}"
  - "**/dispatch*.{ts,js,mjs}"
  - "**/listener*.{ts,js,mjs}"
  - "**/webhook*.{ts,js,mjs}"
references:
  - CWE-696
---

You are reviewing event-dispatching code (switch / map / object
literal that routes event types to handler functions) for cases where
the handler name contradicts the event name — a copy-paste bug that
silently calls the wrong function.

## The bug pattern

```ts
switch (event.type) {
  case "user.removed":
    await dsyncGroupUserAdded(event);   // wrong handler!
    break;
  case "user.added":
    await dsyncGroupUserAdded(event);
    break;
}
```

The cases differ in event type but call the same (or contradictory)
handler. This is almost always a real bug introduced by copying a
case and forgetting to rename the call.

## What to look for

**Switch / case dispatching with mismatched call:**
```ts
case "user.removed":
  await onUserAdded(event);   // "removed" → "Added" — mismatch
```

**Object map dispatching:**
```ts
const handlers = {
  "user.removed": onUserAdded,   // suspicious
  "user.added": onUserAdded,
};
```

**if/else if chains:**
```ts
if (event.type === "subscription.canceled") {
  await onSubscriptionStarted(event);   // mismatch
}
```

**Common verb pairs to flag when mismatched:**
- `added` / `removed`
- `created` / `deleted`
- `enabled` / `disabled`
- `subscribed` / `unsubscribed`
- `installed` / `uninstalled`
- `opened` / `closed`
- `started` / `ended`
- `succeeded` / `failed`
- `granted` / `revoked`

## True positive criteria

Flag when:
1. A dispatch table (switch/case, object map, if-else chain) routes
   event types to handler functions.
2. The event type string and the handler function name include
   conflicting verbs from a known opposite pair.

## What to ignore

- Dispatchers where the same handler legitimately handles multiple
  related events (e.g., a generic `onUserChange` for both add and
  remove).
- Handler names that don't include opposite-verb cues.
- Test files.

## Examples

True positives:
```ts
// Webhook dispatcher with copy-paste bug
switch (event.type) {
  case "dsync.group.user_removed":
    await dsyncGroupUserAdded(event);    // BUG: calls Added on Removed
    break;
  case "dsync.group.user_added":
    await dsyncGroupUserAdded(event);
    break;
}

// Object map with mismatch
const handlers = {
  "subscription.cancelled": onSubscriptionCreated,
  "subscription.created": onSubscriptionCreated,
};
```

False positives to skip:
```ts
// Unified handler — legitimate
switch (event.type) {
  case "user.added":
  case "user.removed":
    await onUserChange(event);   // generic, intentional
    break;
}
```
