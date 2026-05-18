---
slug: android-manifest-export
name: Android Exported Component Without Permission
description: AndroidManifest.xml Activity / Service / Receiver / Provider with android:exported="true" and no android:permission — any installed app can interact with the component.
version: 0.1.0
author: agentgg
mode: file
noiseTier: normal
outputType: finding
filePatterns:
  - "**/AndroidManifest.xml"
references:
  - CWE-926
  - OWASP-Mobile-M1
---

You are reviewing Android `AndroidManifest.xml` files for components
(Activity, Service, BroadcastReceiver, ContentProvider) that are
exported (callable from other apps) without permission protection.
An exported component without a custom permission is a public API
to your app on the device.

## What to look for

**Activity / Service / Receiver / Provider with `android:exported="true"`
and no `android:permission`:**
```xml
<activity android:name=".PrivateActivity"
          android:exported="true">
  <intent-filter>
    <action android:name="com.example.OPEN_INTERNAL" />
  </intent-filter>
</activity>
```
Any other app on the device can start `PrivateActivity` via that
intent action.

**Components with an `intent-filter` but no explicit `exported`
attribute:**
On API < 31 (Android 12), having an `<intent-filter>` made the
component exported by default. On API ≥ 31, `android:exported` is
required when an intent-filter is present.

**`ContentProvider` with public read/write:**
```xml
<provider
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission=""
    android:writePermission="">
</provider>
```
Empty permission strings = no permission required.

**Custom permission with `protectionLevel="normal"`:**
```xml
<permission android:name="com.example.MY_PERM"
            android:protectionLevel="normal" />
```
Normal permissions are auto-granted to any app that requests them —
not real protection. Use `signature` or `signatureOrSystem` for
inter-app permissions intended to be private.

## True positive criteria

Flag when ANY of the following hold:

1. A `<activity>`, `<service>`, `<receiver>`, or `<provider>` has
   `android:exported="true"` AND no `android:permission` attribute
   (and no `android:readPermission`/`android:writePermission` for
   providers).
2. A component has an `<intent-filter>` AND no explicit
   `android:exported` AND the app's `minSdkVersion` is < 31.
3. A custom permission used to protect a component has
   `protectionLevel="normal"` or `"dangerous"` (these don't
   restrict to your own apps).

## What to ignore

- Components that genuinely need to be public (the main launcher
  Activity for the app, share targets, etc.).
- Components protected by a `signature`-level permission.
- Test manifests.

## Examples

True positives:
```xml
<activity android:name=".AdminActivity"
          android:exported="true">
  <intent-filter>
    <action android:name="com.example.ADMIN_OPEN" />
  </intent-filter>
</activity>

<receiver android:name=".InternalReceiver"
          android:exported="true">
  <intent-filter>
    <action android:name="com.example.INTERNAL_BROADCAST" />
  </intent-filter>
</receiver>
```

False positives to skip:
```xml
<activity android:name=".MainActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.MAIN" />
    <category android:name="android.intent.category.LAUNCHER" />
  </intent-filter>
</activity>

<service android:name=".InternalService"
         android:exported="true"
         android:permission="com.example.permission.INTERNAL" />
<!-- com.example.permission.INTERNAL declared with signature protectionLevel -->
```
