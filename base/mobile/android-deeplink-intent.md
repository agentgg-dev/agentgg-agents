---
slug: android-deeplink-intent
name: Android Deep-Link / Intent Handling Vulnerabilities
description: 'Exported Android Activities/Services whose incoming intent data (getIntent().getData(), getStringExtra, onNewIntent) flows unvalidated into WebView loadUrl, file/SQL sinks; hijackable implicit intents; mutable PendingIntents with implicit base intents; ContentProvider params concatenated into SQL. Reads AndroidManifest.xml together with the handler source.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '<intent-filter|android:exported\s*=\s*"true"|<data\s+android:scheme'
        in:
          - '**/AndroidManifest.xml'
        label: Manifest declares an intent-filter / exported component / deep-link scheme
      - regex: '(getIntent\s*\(\s*\)|onNewIntent|getData\s*\(\s*\)|getStringExtra|getQueryParameter)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Code reads incoming intent / deep-link data
      - regex: 'PendingIntent\.(getActivity|getService|getBroadcast)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: PendingIntent construction
  prompt: Run only if this is an Android app — confirm via AndroidManifest.xml / build.gradle and intent-handling code.
where:
  extensions:
    - java
    - kt
  filePatterns:
    - '**/AndroidManifest.xml'
  excludePatterns:
    - '**/__tests__/**'
    - '**/tests/**'
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
    - '**/vendor/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '<intent-filter'
      label: Component with an intent-filter (deep link / App Link entry point)
    - regex: '<data\s+android:(scheme|host|pathPrefix)'
      label: Deep-link data element
    - regex: 'android:exported\s*=\s*"true"'
      label: Exported component
    - regex: '(getIntent\s*\(\s*\)|onNewIntent)'
      label: Activity reads its launching intent
    - regex: '\.(getData|getDataString|getStringExtra|getParcelableExtra|getQueryParameter)\s*\('
      label: Reads untrusted data/extra from an intent
    - regex: '\.loadUrl\s*\(|\.loadData(WithBaseURL)?\s*\('
      label: WebView load sink
    - regex: '(rawQuery|execSQL)\s*\(|SELECTION'
      label: ContentProvider / SQLite query sink
    - regex: 'PendingIntent\.(getActivity|getService|getBroadcast)'
      label: PendingIntent (check for FLAG_MUTABLE / missing FLAG_IMMUTABLE)
    - regex: 'FLAG_MUTABLE'
      label: Explicitly mutable PendingIntent
references:
  - CWE-927
  - CWE-939
  - CWE-89
  - OWASP-Mobile-M1
---

You are reviewing Android deep-link and intent handling for
vulnerabilities where attacker-controlled intent data reaches a
sensitive sink, or an intent leaves your app exposed to hijacking. The
attacker is a malicious co-installed app sending a crafted intent, or
any web page / link that fires your `scheme://` deep link or App Link.
The trust boundary is the inter-app / link boundary: anything arriving
through `getIntent()` / `onNewIntent` / a `<data>` deep link is
untrusted.

## Cross-file analysis

This bug spans two files. The manifest declares which component is
exported and which intent-filter / deep-link scheme reaches it; the
actual handling is in the Activity/Service source. Open both:

- In `AndroidManifest.xml`, find components that are reachable from
  other apps or the web: `android:exported="true"`, or an
  `<intent-filter>` with `<action android:name="...VIEW">` +
  `<data android:scheme="...">` (deep link / App Link). On API < 31 an
  intent-filter implies exported even without the attribute.
- Then open the named Activity/Service. Follow the intent data
  (`getIntent().getData()`, `getStringExtra(...)`, `onNewIntent`) to
  where it is used. The source (manifest entry point) and the sink
  (WebView, file, SQL) are in different files.
- For App Links, the host is OS-verified only if
  `android:autoVerify="true"` and the assetlinks file is published;
  path/query parameters are still attacker-controlled.

## What to look for

**Deep-link data flowing into WebView `loadUrl` (lets a link load an
attacker URL / `javascript:` into your authenticated WebView):**
```kotlin
val target = intent.data?.getQueryParameter("url")
webView.loadUrl(target!!)
```

**Intent extra flowing into file access (path traversal across apps):**
```java
String name = getIntent().getStringExtra("file");
File f = new File(getFilesDir(), name);
```

**ContentProvider query params concatenated into SQL:**
```java
public Cursor query(Uri uri, ..., String selection, ...) {
    String id = uri.getLastPathSegment();
    return db.rawQuery("SELECT * FROM notes WHERE id = " + id, null);
}
```

**Mutable PendingIntent wrapping an implicit base intent (a malicious
app can fill in the blanks and run it with your identity):**
```java
Intent base = new Intent();            // implicit, no component set
PendingIntent pi = PendingIntent.getActivity(
    ctx, 0, base, PendingIntent.FLAG_MUTABLE);
```
Also flag `PendingIntent.getActivity(...)` on API 31+ created without
`FLAG_IMMUTABLE` and without `FLAG_MUTABLE` set defensively.

**Implicit intent for a sensitive action (can be intercepted):**
```java
Intent i = new Intent("com.example.PROCESS_PAYMENT");  // no setPackage
sendBroadcast(i);
```

**Trusting the launching intent for authorization** — reflecting an
extra back, or treating `getIntent()` data as already-authenticated.

## True positive criteria

A finding is real when untrusted intent / deep-link data crosses the
inter-app or link trust boundary into a sink without validation. State:

- The attacker: "a malicious app I co-install" or "an attacker who
  gets the victim to open a `myapp://...` link / App Link".
- The first-person capability: "I can send an intent / open a link that
  makes the app load my URL in its WebView" / "read an arbitrary file"
  / "inject SQL via the provider" / "trigger your PendingIntent as
  you".
- The trust boundary: the component is exported (explicitly, or via an
  intent-filter on API < 31) or reachable by deep link, so my crafted
  data reaches the handler.

Flag when:
1. A component is exported / deep-link-reachable (confirm in manifest), AND
2. its handler reads intent data (`getData`, `getStringExtra`,
   `getQueryParameter`, `onNewIntent`), AND
3. that data reaches a sink — `loadUrl`/`loadData`, file path, raw SQL,
   another intent, or an auth decision — without validation; OR
4. a `PendingIntent` is mutable (`FLAG_MUTABLE`, or no `FLAG_IMMUTABLE`
   on API 31+) AND its base intent is implicit (no explicit
   component/package); OR
5. a sensitive implicit intent is sent without `setPackage` /
   explicit component.

## What to ignore

- Components exported but protected by a `signature`-level
  `android:permission`, or not exported at all
  (`android:exported="false"` and no intent-filter on API >= 31).
- Intent data that is strictly validated (allowlisted host/scheme,
  parsed ID checked, path canonicalized and confined) before the sink.
- `PendingIntent` with `FLAG_IMMUTABLE`, or with an explicit base
  intent (component/package set) — not hijackable.
- WebView `loadUrl` with a hardcoded/allowlisted URL, or
  `loadUrl("javascript:...")` the app itself controls.
- ContentProvider queries using parameterized `selectionArgs` / `?`
  placeholders instead of concatenation.
- Non-sensitive navigation (just opening a screen) with no
  side-effecting sink and no auth decision based on the intent.
- Test manifests and instrumentation code.

## Examples

True positives:
```kotlin
override fun onCreate(b: Bundle?) {
    val url = intent.data?.getQueryParameter("redirect")
    webView.loadUrl(url!!)          // attacker link controls the URL
}
```
```java
PendingIntent pi = PendingIntent.getBroadcast(
    ctx, 0, new Intent(), PendingIntent.FLAG_MUTABLE);  // implicit + mutable
```
Manifest for the first (exported VIEW deep link):
```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <data android:scheme="myapp" android:host="open"/>
  </intent-filter>
</activity>
```

False positives to skip:
```kotlin
val host = intent.data?.host
if (host == "open" && allowedPaths.contains(intent.data?.path)) {
    navigateTo(intent.data!!.path!!)   // validated, no side effect
}
```
```java
Intent base = new Intent(ctx, PayActivity.class);   // explicit component
PendingIntent pi = PendingIntent.getActivity(
    ctx, 0, base, PendingIntent.FLAG_IMMUTABLE);
```
```java
Cursor c = db.rawQuery(
    "SELECT * FROM notes WHERE id = ?", new String[]{ id });
```
