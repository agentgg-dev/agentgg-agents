---
slug: android-provider-path
name: Android Insecure FileProvider Root Path
description: 'FileProvider configured with root-path and a wildcard or empty path attribute, exposing the entire device filesystem or storage root to other apps via content:// URIs — allows reading arbitrary app files.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'FileProvider|root-path'
        in:
          - '**/res/xml/*.xml'
          - '**/AndroidManifest.xml'
          - '**/*provider_paths*.xml'
          - '**/*file_paths*.xml'
        notIn:
          - '**/build/**'
          - '**/node_modules/**'
        label: FileProvider or root-path configuration present
where:
  extensions:
    - xml
  excludePatterns:
    - '**/build/**'
    - '**/node_modules/**'
    - '**/vendor/**'
  preFilter:
    - regex: 'root-path\s+name='
      label: root-path element in FileProvider XML
references:
  - CWE-200
  - CWE-732
---

You are reviewing Android FileProvider configuration files for insecure `root-path` declarations that expose the device filesystem to other apps.

## How FileProvider works

FileProvider is an Android `ContentProvider` subclass that grants other apps read/write access to specific files via `content://` URIs. The `paths` XML file controls which directories are accessible.

The available path types:
- `files-path` — app's internal files directory
- `cache-path` — app's cache directory
- `external-files-path` — app's external storage directory
- `external-cache-path` — app's external cache directory
- **`root-path`** — the device's filesystem root (`/`) — dangerous

## The vulnerability

`root-path` with a wildcard or empty `path` attribute exposes the entire filesystem:
```xml
<!-- VULNERABLE: exposes entire filesystem -->
<root-path name="root" path="." />
<root-path name="storage" path="" />

<!-- Also vulnerable: paths starting from / reach sensitive files -->
<root-path name="files" path="/data/data/com.app/" />
```

When `path="."` or `path=""`, the FileProvider can serve any file on the device — including the app's private databases, shared preferences, and OAuth tokens — to any app that requests a `content://` URI.

An attacker with a malicious app installed on the same device can:
1. Trigger the vulnerable app to share a file
2. Request `content://com.vulnerable.app.provider/../../../data/data/com.app/databases/tokens.db`
3. Read sensitive data from the returned stream

## True positive criteria

Flag when `root-path` appears with:
- `path="."` — grants access from filesystem root
- `path=""` — equivalent to root
- Any path that starts at a location higher than the app's own sandboxed directories

## What to ignore

- `files-path`, `cache-path`, `external-files-path`, `external-cache-path` — scoped to app's own storage, safe
- `root-path name="..." path="/sdcard/..."` with a specific external storage directory — narrowly scoped, lower risk but still worth noting

## Safe configuration

```xml
<paths>
    <files-path name="shared_files" path="shared/" />
    <cache-path name="cache" path="cache_images/" />
</paths>
```

Report: the exact `root-path` element found, the `path` attribute value, and the FileProvider authority name from `AndroidManifest.xml` if visible.
