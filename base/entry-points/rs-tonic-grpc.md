---
slug: rs-tonic-grpc
name: Tonic gRPC Service Entry Points
description: Locates Tonic gRPC service trait implementations and Status responses via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [tonic]
noiseTier: noisy
filePatterns:
  - "**/*.rs"
excludePatterns:
  - "**/tests/**"
  - "**/examples/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/target/**"
preFilter:
  - regex: "#\\[\\s*tonic::async_trait\\s*\\]"
    label: "#[tonic::async_trait] impl"
  - regex: "\\bimpl\\s+\\w+\\s+for\\s+\\w+\\s*\\{"
    label: "service trait implementation"
  - regex: "\\bRequest<[^>]+>|\\bResponse<[^>]+>"
    label: "Request/Response shape"
  - regex: "\\bStatus::(?:unauthenticated|permission_denied|invalid_argument)"
    label: "Status response"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Tonic gRPC service implementations
and `Status::*` error responses.

Gated on `tech: [tonic]` — only runs when `fingerprint(root)` detects
Tonic.

## What this finds

- `#[tonic::async_trait]` impl attributes
- `impl Service for Impl { }` service trait implementations
- `Request<T>` / `Response<T>` shapes
- `Status::unauthenticated` / `permission_denied` / `invalid_argument`
  responses

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
