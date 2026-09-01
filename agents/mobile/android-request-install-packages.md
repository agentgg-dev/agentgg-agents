---
slug: android-request-install-packages
name: Android REQUEST_INSTALL_PACKAGES Permission
description: 'AndroidManifest.xml declares REQUEST_INSTALL_PACKAGES permission, allowing the app to install arbitrary APKs outside the Play Store. Abused by malware for dropper-style attacks and auto-update mechanisms that bypass security review.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'REQUEST_INSTALL_PACKAGES'
        in:
          - '**/AndroidManifest.xml'
        notIn:
          - '**/build/**'
        label: REQUEST_INSTALL_PACKAGES declared in AndroidManifest
where:
  filePatterns:
    - '**/AndroidManifest.xml'
  excludePatterns:
    - '**/build/**'
    - '**/node_modules/**'
  preFilter:
    - regex: 'REQUEST_INSTALL_PACKAGES'
      label: REQUEST_INSTALL_PACKAGES permission
references:
  - CWE-494
---

You are reviewing AndroidManifest.xml for the `REQUEST_INSTALL_PACKAGES` permission, which allows the app to install arbitrary APKs on the device.

## The permission

```xml
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
```

This permission (introduced in Android 8.0, API 26) allows an app to trigger APK installations from unknown sources. Before API 26, apps used the `INSTALL_PACKAGES` permission or redirected to the system installer.

## Why this is a risk

1. **Dropper behavior:** The app can silently download and prompt the user to install a malicious APK — a common technique in adware and banking trojans.
2. **Auto-update bypass:** The app can ship updates that bypass Google Play security review, installing modified APKs with new permissions or malicious code.
3. **Supply chain:** If the app is compromised (CDN, server, or build pipeline), this permission enables attackers to deliver a backdoored update to all users.

## What to check after finding this permission

Look for code that:
1. Downloads APK files from external URLs: `OkHttpClient`, `HttpURLConnection`, `DownloadManager` fetching `.apk` files
2. Calls `Intent(Intent.ACTION_INSTALL_PACKAGE)` or `PackageInstaller` with a downloaded file
3. Installs APKs from external storage or app-writable directories

## Severity guidance

Flag at high:
1. `REQUEST_INSTALL_PACKAGES` declared AND code that downloads and installs APKs from external or user-controlled URLs

Flag at medium:
2. `REQUEST_INSTALL_PACKAGES` declared for a consumer app with no obvious legitimate use (not an MDM, app store, or enterprise management tool)

Note only (not a vulnerability):
3. Present in an MDM app, enterprise store, or app explicitly designed to install other apps — legitimate use case

Report: the permission declaration, any code found that downloads or installs APKs, and whether the download source is hardcoded (lower risk) or dynamically configured (higher risk).
