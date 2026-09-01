---
slug: mapbox-api-key
name: Mapbox Secret Token Exposure
description: 'Hardcoded Mapbox secret access tokens (sk. prefix, 80-240 chars) in source or config. Secret tokens grant write access to Mapbox datasets, styles, and tilesets — unlike public tokens which are read-only.'
version: 0.1.0
author: agentgg
noiseTier: normal
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\bsk\.[a-zA-Z0-9.]{80,240}\b'
      label: Mapbox secret token (sk. prefix, 80-240 chars)
    - regex: '(?i)(?:mapbox|MAPBOX_SECRET_TOKEN).{0,30}[=:"''\s]+sk\.[a-zA-Z0-9.]{80,}'
      label: Mapbox secret token in named variable
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Mapbox secret access tokens. Mapbox provides mapping, geocoding, and navigation APIs.

## Token types

**Public token (`pk.`):** read-only access to public tilesets and styles. Intended to be in client-side code. NOT a secret.

**Secret token (`sk.`):** write access — can create and delete datasets, styles, and tilesets, and generate new tokens. Should only be in server-side code.

## Token format

```
sk.<80-240 alphanumeric/dot characters>
```

## What a leaked secret token enables

- Create, modify, and delete map styles and tilesets
- Upload geodata to Mapbox datasets
- Generate new access tokens (persistence and lateral movement)
- Incur billing charges via API usage
- Access private datasets

## True positive criteria

Flag when ALL hold:
1. Value starts with `sk.` and is 80-240 chars total
2. Mapbox context confirmed (import, `mapboxgl`, `MAPBOX` variable name nearby)
3. String literal, not an env var reference
4. Not a public token (`pk.`) — those are intentionally public

## What to ignore

- Public tokens (`pk.` prefix) — designed to be in browser code
- Mapbox token URLs or documentation references

## Examples

True positive:
```js
const mapboxClient = require('@mapbox/mapbox-sdk');
const client = mapboxClient({ accessToken: 'sk.eyJ1IjoiZXhhbXBsZSIsImEiOiJ...' });
```

Report whether the token appears in server-side or client-side code.
