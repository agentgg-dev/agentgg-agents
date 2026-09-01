---
slug: openapi-schema-gaps
name: OpenAPI Schema Gaps (Mass Assignment / Unbounded Input)
description: 'OpenAPI / JSON Schema request definitions that permit mass-assignment / overposting and unbounded input — additionalProperties true or omitted, missing required, strings without maxLength/pattern, integers without minimum/maximum, arrays without maxItems. Scoped to OpenAPI/Swagger spec files.'
version: 0.1.0
author: agentgg
noiseTier: noisy
precondition:
  regex:
    patterns:
      - regex: '^\s*[''"]?(openapi|swagger)[''"]?\s*:\s*[''"]?[0-9]'
        in:
          - '**/*.{yaml,yml}'
          - '**/*.json'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: OpenAPI/Swagger spec marker
where:
  filePatterns:
    - '**/*.{yaml,yml}'
    - '**/*.json'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.terraform/**'
  preFilter:
    - semgrepRule: misconfiguration/openapi-spec
      label: OpenAPI version marker or additionalProperties gap
    - regex: '(openapi|swagger)\s*:\s*[''"]?[0-9]'
      label: OpenAPI/Swagger version marker
    - regex: 'additionalProperties\s*:\s*true'
      label: additionalProperties true
    - regex: 'requestBody|[''"]?in[''"]?\s*:\s*[''"]?(query|path|header)'
      label: request body / parameter
    - regex: '[''"]?type[''"]?\s*:\s*[''"]?(object|string|integer|number|array)'
      label: schema type declaration
references:
  - CWE-915
  - CWE-20
  - 'OWASP-API6:2023'
---

You are reviewing OpenAPI / Swagger specification files for schema gaps
that invite mass-assignment / overposting and unbounded input. A loose
request schema is a server-side control failure: code generators,
request validators, and gateways trust the spec, so an attacker submits
extra or oversized fields the endpoint never intended to accept.

First confirm the file IS an OpenAPI/Swagger doc — it has a top-level
`openapi: 3.x` or `swagger: 2.0`. Plain config/CI YAML and JSON are out
of scope even if they contain a `type:` key.

**Cross-file analysis:** schemas are usually defined once under
`components/schemas` (OAS3) or `definitions` (Swagger2) and reused via
`$ref`. A `requestBody` may `$ref` a shared schema, and that schema may
`allOf`-compose other schemas. To judge a request body, resolve the
`$ref` chain to the actual object schema. A gap in a shared schema
affects every operation that references it. Also follow split specs
(`$ref: "./schemas/user.yaml#/User"`) into the referenced file.

## What to look for

**Object schema that allows arbitrary extra properties (overposting):**
```yaml
User:
  type: object
  properties:
    name: { type: string }
  additionalProperties: true
```
`additionalProperties: true` — OR omitted entirely on an object used as
a request body — lets a client send `isAdmin: true`, `role`, `balance`,
etc. The server-side binder may copy them onto the model.

**No `required`, so every field is optional / silently defaulted:**
```yaml
requestBody:
  content:
    application/json:
      schema:
        type: object
        properties:
          email: { type: string }
          role:  { type: string }
```
Missing `required:` means partial/empty bodies validate, and combined
with loose props the client controls which fields appear.

**Unbounded strings (no maxLength / no pattern):**
```yaml
username: { type: string }
```
No `maxLength` and no `pattern` — accepts megabyte payloads and
arbitrary content (ReDoS bait, injection vehicles, storage abuse).

**Unbounded integers / numbers (no minimum / maximum):**
```yaml
quantity: { type: integer }
limit:    { type: integer }
```
No `minimum`/`maximum` — negative quantities, integer overflow, or a
`limit` of 2_000_000 that DoSes the database.

**Unbounded arrays (no maxItems):**
```yaml
ids:
  type: array
  items: { type: string }
```
No `maxItems` — a client posts a million-element array.

## True positive criteria

A finding is a request-side schema (`requestBody`, or a parameter with
`in: query|path|header`, or a `$ref` target reachable from one) that the
spec leaves loose. Name the attacker and the trust boundary: the
attacker is "any client of this API"; the trust boundary is the
HTTP request body/params the spec tells the framework to accept. I can:

- Add unlisted fields when `additionalProperties` is `true` or omitted
  on a request object -> overpost privileged fields.
- Omit or oversize fields when `required` is missing and string/number/
  array bounds are absent -> bypass intended constraints, send oversized
  input.

The burden is on the spec to constrain input. Because this tier is
NOISY, report each loose request schema, but prefer the ones where the
field name suggests privilege or size impact (`role`, `isAdmin`,
`status`, `price`, `*_id`, `limit`, `count`, free-text bodies).

## What to ignore

- Schemas that already lock it down: `additionalProperties: false` on
  the object, a present `required:` list, strings with `maxLength`
  and/or `pattern`, integers with `minimum`/`maximum`, arrays with
  `maxItems`. A schema with all relevant constraints is NOT a finding.
- `additionalProperties` set to a schema (e.g.
  `additionalProperties: { type: string }`) used for a genuine
  map/dictionary field — that is intentional, constrained, and not
  overposting. Only `true` (or omitted on a request object) is the gap.
- RESPONSE schemas (`responses:` / read-only `$ref` targets used only in
  responses). Overposting and input-bounding apply to inbound data, not
  to what the server returns. A property marked `readOnly: true` is also
  not client-assignable.
- `enum`-constrained fields and `$ref`-to-constrained-schema — the
  constraint lives in the referenced schema; resolve it before flagging.
- Booleans and well-bounded primitives where no bound is meaningful
  (e.g. a `boolean`, or a `string` with `format: date` enforced by the
  validator), unless string length still matters.
- Non-OpenAPI YAML/JSON that merely contains `type:` (CI configs,
  k8s manifests, package manifests) — the precondition should exclude
  these, but skip them if one slips through.

## Examples

True positives:
```yaml
CreateUser:
  type: object
  properties:
    email: { type: string }
    name:  { type: string }
```
(object request body, no `additionalProperties: false`, no `required`,
no string bounds — overposting + unbounded.)
```yaml
parameters:
  - in: query
    name: limit
    schema: { type: integer }
```
(no `minimum`/`maximum` — `limit=99999999`.)
```yaml
Order:
  type: object
  additionalProperties: true
  properties:
    item: { type: string }
```
(`additionalProperties: true` on a request object — send `status: paid`.)

False positives to skip:
```yaml
CreateUser:
  type: object
  additionalProperties: false
  required: [email]
  properties:
    email: { type: string, maxLength: 254, format: email }
    name:  { type: string, maxLength: 100 }
```
```yaml
parameters:
  - in: query
    name: limit
    schema: { type: integer, minimum: 1, maximum: 100 }
```
```yaml
Settings:
  type: object
  additionalProperties: { type: string, maxLength: 200 }
```
(constrained map value — intentional, not overposting.)
