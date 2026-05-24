---
slug: rs-lambda-runtime
name: Rust AWS Lambda Runtime Entry Points
description: Locates Rust AWS Lambda handler registrations and event shapes via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [lambda-rs]
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
  - regex: "\\blambda_runtime::run\\s*\\(\\s*service_fn\\s*\\("
    label: "lambda_runtime::run(service_fn(handler))"
  - regex: "\\bLambdaEvent<[^>]+>"
    label: "LambdaEvent shape"
  - regex: "\\baws_lambda_events::"
    label: "AWS event types (APIGatewayProxyRequest, etc.)"
references:
  - CWE-862
  - CWE-285
---

Regex-only rule (no LLM). Locates Rust AWS Lambda handler
registrations, event shapes, and AWS event type imports.

Gated on `tech: [lambda-rs]` — only runs when `fingerprint(root)`
detects the Rust Lambda runtime.

## What this finds

- `lambda_runtime::run(service_fn(handler))` registration
- `LambdaEvent<T>` event shapes
- `aws_lambda_events::*` event type imports
  (`ApiGatewayProxyRequest`, `SqsEvent`, etc.)

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
