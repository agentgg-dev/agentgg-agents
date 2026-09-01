---
slug: cloudinary-credentials
name: Cloudinary Credentials Exposure
description: 'Hardcoded Cloudinary connection strings (cloudinary://api_key:api_secret@cloud_name) or individual API secrets in source or config. A leaked credential allows uploading, deleting, and transforming all media assets in the account.'
version: 0.1.0
author: agentgg
noiseTier: precise
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
    - regex: 'cloudinary://[0-9]+:[A-Za-z0-9\-_\.]+@[A-Za-z0-9\-_\.]+'
      label: Cloudinary connection string (cloudinary://key:secret@name)
    - regex: '(?i)cloudinary.{0,30}api_secret.{0,10}[=:][''"\s]{0,3}[A-Za-z0-9\-_]{27}'
      label: Cloudinary API secret near cloudinary keyword
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Cloudinary credentials.

## Credential formats

**Connection URL:** `cloudinary://{api_key}:{api_secret}@{cloud_name}` — contains all three required credentials in a single string.

**Individual credentials:** Cloudinary authentication requires three values together:
- `cloud_name` — the Cloudinary account identifier (semi-public)
- `api_key` — numeric identifier (~15 digits)
- `api_secret` — a 27-character alphanumeric secret

The `api_secret` alone (without `cloud_name` and `api_key`) is not directly exploitable, but finding it alongside the other values is a complete credential set.

## Risk

An attacker with Cloudinary credentials can:
- Upload unlimited files to the account — enables hosting malware, phishing pages, or illegal content on the victim's CDN
- List, download, and exfiltrate all stored media assets — images, videos, documents, and other files
- Delete or overwrite existing assets — causing service disruption or defacement if assets are production images
- Access transformation URLs with the signature — bypass signed URL restrictions
- Modify upload presets and transformation pipelines — potentially affecting how user-uploaded content is processed

## Cross-file analysis

When a connection URL or individual credentials are found, look for:
1. The `cloud_name` in the same file — identifies the Cloudinary account
2. Upload preset names — determines how assets are processed and whether unsigned uploads are allowed
3. Whether the code handles user uploads — attacker can upload malicious content through the application's own workflows

## True positive criteria

Flag when ALL hold:
1. A complete Cloudinary connection URL (`cloudinary://key:secret@name`) is present, OR the `api_secret` appears alongside `api_key` and `cloud_name`
2. The values are string literals, not environment variable references (`process.env.CLOUDINARY_URL`, `process.env.CLOUDINARY_API_SECRET`)
3. Not placeholder values in documentation or Cloudinary's own getting-started guides

Note: `CLOUDINARY_URL` is a common environment variable pattern. Only flag if the actual value is embedded, not if the code reads from an environment variable.

## What to ignore

- `CLOUDINARY_URL` environment variable references: `cloudinary.config({ url: process.env.CLOUDINARY_URL })`
- The `cloud_name` alone or the `api_key` alone — both are effectively public; the `api_secret` is the sensitive component
- SDK configuration that only uses `cloud_name` without credentials (for public asset delivery)

## Examples

True positives:
```python
cloudinary.config(cloud_name='mystore', api_key='<api-key>', api_secret='<api-secret>')
```
```yaml
CLOUDINARY_URL: cloudinary://<api-key>:<api-secret>@mystore
```
```ts
cloudinary.config({
  cloud_name: 'mystore',
  api_key: '<api-key>',
  api_secret: '<api-secret>',
});
```

False positives to skip:
```ts
cloudinary.config({ url: process.env.CLOUDINARY_URL });
```
```ts
// Only cloud_name — for public delivery, no secret needed
const cld = new Cloudinary({ cloud: { cloudName: 'mystore' } });
```

Note the cloud_name to identify the account and whether the code handles user uploads (upload paths are more dangerous than read-only asset delivery).
