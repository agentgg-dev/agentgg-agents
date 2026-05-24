---
slug: clj-ring-handler
name: Clojure Ring/Compojure Handler Entry Points
description: Locates Clojure Ring/Compojure routes, handler fns, and wrap-* middleware via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [clojure]
noiseTier: noisy
filePatterns:
  - "**/*.clj"
  - "**/*.cljs"
  - "**/*.cljc"
excludePatterns:
  - "**/test/**"
  - "**/spec/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/target/**"
preFilter:
  - regex: "\\bdefroutes\\b"
    label: "defroutes Compojure declaration"
  - regex: "\\((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\\s+\"[^\"]+\""
    label: "Compojure route verb"
  - regex: "\\bdefn\\s+\\w+\\s+\\[\\s*(?:request|req)\\b"
    label: "Ring handler fn (request-shape arg)"
  - regex: "\\bwrap-(?:authentication|authorization|cors|csrf)\\b"
    label: "Ring middleware"
references:
  - CWE-862
  - CWE-352
---

Regex-only rule (no LLM). Locates Clojure Ring/Compojure routes,
handler functions, and `wrap-*` middleware.

Gated on `tech: [clojure]` — only runs when `fingerprint(root)`
detects Clojure.

## What this finds

- `defroutes` Compojure declarations
- Compojure route verbs (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`,
  `HEAD`, `OPTIONS`, `ANY`)
- Ring handler functions (`(defn name [request] ...)`)
- `wrap-authentication` / `wrap-authorization` / `wrap-cors` /
  `wrap-csrf` middleware

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
