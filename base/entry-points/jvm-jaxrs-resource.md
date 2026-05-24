---
slug: jvm-jaxrs-resource
name: JAX-RS Resource Entry Points
description: Locates JAX-RS resources (Jersey, RESTEasy, Quarkus) — @Path/@GET/@POST declarations and auth annotations — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [jaxrs]
noiseTier: noisy
filePatterns:
  - "**/*.java"
  - "**/*.kt"
excludePatterns:
  - "**/test/**"
  - "**/tests/**"
  - "**/src/test/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/target/**"
preFilter:
  - regex: "@Path\\s*\\(\\s*\"[^\"]+\"\\s*\\)"
    label: "@Path declaration"
  - regex: "@(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\b"
    label: "JAX-RS method annotation"
  - regex: "@RolesAllowed\\s*\\("
    label: "@RolesAllowed auth gate"
  - regex: "@PermitAll\\b"
    label: "@PermitAll opens public access"
  - regex: "@(?:Path|Query|Header|Form|Cookie)Param\\s*\\("
    label: "param extractor (untrusted)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates JAX-RS resources (Jersey,
RESTEasy, Quarkus): `@Path` declarations, HTTP-method annotations,
auth annotations, and `@*Param` extractors.

Gated on `tech: [jaxrs]` — only runs when `fingerprint(root)` detects
a JAX-RS implementation.

## What this finds

- `@Path("/...")` resource declarations
- `@GET` / `@POST` / `@PUT` / `@PATCH` / `@DELETE` / `@HEAD` /
  `@OPTIONS` method annotations
- `@RolesAllowed(...)` auth gates
- `@PermitAll` — opens public access (verify intent)
- `@PathParam` / `@QueryParam` / `@HeaderParam` / `@FormParam` /
  `@CookieParam` — untrusted input extractors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
