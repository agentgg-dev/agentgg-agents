---
slug: php-wordpress-rest
name: WordPress REST Entry Points
description: Locates WordPress REST routes, AJAX hooks, shortcodes, and superglobal accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [wordpress]
noiseTier: noisy
filePatterns:
  - "**/*.php"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/wp-includes/**"
  - "**/wp-admin/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "register_rest_route\\s*\\("
    label: "register_rest_route() — REST endpoint"
  - regex: "add_action\\s*\\(\\s*['\"]wp_ajax_(?:nopriv_)?[^'\"]+['\"]"
    label: "wp_ajax_*/wp_ajax_nopriv_* hook (nopriv = unauthenticated)"
  - regex: "add_shortcode\\s*\\("
    label: "add_shortcode() — user-content surface"
  - regex: "'permission_callback'\\s*=>\\s*'__return_true'"
    label: "permission_callback => __return_true (public REST route)"
  - regex: "\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\\b"
    label: "PHP superglobal (untrusted input)"
references:
  - CWE-862
  - CWE-306
  - CWE-20
---

Regex-only rule (no LLM). Locates WordPress REST routes, AJAX hooks,
shortcodes, and direct superglobal accessors.

Gated on `tech: [wordpress]` — only runs when `fingerprint(root)`
detects WordPress.

## What this finds

- `register_rest_route(...)` REST endpoint declarations
- `add_action('wp_ajax_*', ...)` / `add_action('wp_ajax_nopriv_*',
  ...)` — `nopriv` is unauthenticated
- `add_shortcode(...)` user-content surfaces
- `permission_callback => '__return_true'` — public REST route
- Direct superglobal access (`$_GET`, `$_POST`, `$_REQUEST`,
  `$_COOKIE`, `$_SERVER`) — untrusted input

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
