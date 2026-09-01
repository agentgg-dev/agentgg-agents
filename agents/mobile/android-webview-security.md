---
slug: android-webview-security
name: Android WebView Security Misconfigurations
description: 'Android WebView configured with JavaScript enabled, file/universal access, addJavascriptInterface, or SSL error bypass — these settings expand the attack surface from web content to native app code and the local filesystem.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|addJavascriptInterface|onReceivedSslError|SslErrorHandler'
        in:
          - '**/*.java'
          - '**/*.kt'
          - '**/*.smali'
        notIn:
          - '**/test/**'
          - '**/androidTest/**'
        label: Android WebView security setting
where:
  extensions:
    - java
    - kt
    - smali
  excludePatterns:
    - '**/test/**'
    - '**/androidTest/**'
    - '**/build/**'
  preFilter:
    - regex: 'setJavaScriptEnabled\s*\(\s*true\s*\)'
      label: JavaScript enabled in WebView
    - regex: 'setAllowFileAccess\s*\(\s*true\s*\)'
      label: File access enabled in WebView
    - regex: 'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)'
      label: Universal file URL access enabled
    - regex: 'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)'
      label: Cross-file-URL access enabled
    - regex: 'addJavascriptInterface\s*\('
      label: Native interface exposed to JavaScript
    - regex: 'onReceivedSslError|SslErrorHandler.*proceed\(\)'
      label: SSL error suppressed in WebView
    - regex: 'Landroid/webkit/WebSettings;->setJavaScriptEnabled|Landroid/webkit/WebView;->addJavascriptInterface|Landroid/webkit/SslErrorHandler;->proceed'
      label: WebView security call in smali
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-749
  - CWE-295
  - OWASP-Mobile-M1
---

You are reviewing Android source code for WebView security misconfigurations. Each setting below expands the WebView attack surface in a different way.

## Vulnerability classes

### 1. JavaScript enabled (`setJavaScriptEnabled(true)`)

JavaScript is disabled in Android WebViews by default. Enabling it is often necessary for web content but introduces risk:
- If the WebView loads remote content, XSS in that content runs in the WebView's context
- If `addJavascriptInterface` is also used, XSS escalates to native code execution

**Flag when:** JavaScript is enabled AND the WebView loads remote or user-supplied URLs. Loading only trusted local assets is lower risk.

### 2. File access (`setAllowFileAccess(true)`)

Allows the WebView to access files via `file://` URIs. Combined with JavaScript:
- An attacker who can control the WebView's URL (e.g., via a deep link or intent) can load `file:///data/data/com.app/shared_prefs/secrets.xml` and exfiltrate it via JavaScript

**Flag when:** `setAllowFileAccess(true)` AND JavaScript is enabled.

### 3. Universal file URL access (`setAllowUniversalAccessFromFileURLs(true)`)

Allows JavaScript running in a `file://` page to make XHR/fetch requests to any other `file://` URL — full local file read via JavaScript. This is a direct path to credential theft.

**Flag always** — there is almost no legitimate use case.

### 4. Cross-file URL access (`setAllowFileAccessFromFileURLs(true)`)

Similar to universal access but scoped to `file://` origins. Still allows a malicious local HTML page to read arbitrary local files.

**Flag always** unless the files loaded are fully developer-controlled (no user content).

### 5. addJavascriptInterface

Exposes a Java/Kotlin object's methods to JavaScript. Any XSS in the WebView can call these methods:
```java
webView.addJavascriptInterface(new FileHelper(), "AndroidBridge");
// JS: AndroidBridge.readFile("/data/data/com.app/databases/creds.db")
```

**Flag when:** the exposed object has sensitive methods (file I/O, network, crypto, shell) AND the WebView loads any remote or user-controlled content.

### 6. SSL error bypass (`onReceivedSslError` calling `handler.proceed()`)

```java
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    handler.proceed(); // VULNERABLE — ignores all SSL errors
}
```

Calling `handler.proceed()` unconditionally accepts any SSL certificate, disabling HTTPS validation. This opens the app to MITM attacks on all WebView traffic.

**Flag always** — `handler.proceed()` is never safe for production code.

## Cross-file analysis

1. Find the `WebView` setup code — often in an Activity or Fragment's `onCreate`
2. Check what URL/content the WebView loads: `loadUrl()`, `loadData()`, `loadDataWithBaseURL()` — is the content remote, local-only, or user-supplied?
3. If `addJavascriptInterface` is used, read the exposed class to assess what methods are accessible from JavaScript
4. Look for the `WebViewClient` implementation — find `onReceivedSslError`

## True positive criteria

| Setting | Condition for finding |
|---|---|
| setJavaScriptEnabled(true) | Loads remote or user-controlled URLs |
| setAllowFileAccess(true) | JavaScript is also enabled |
| setAllowUniversalAccessFromFileURLs(true) | Always |
| setAllowFileAccessFromFileURLs(true) | JavaScript is also enabled |
| addJavascriptInterface | Exposed class has sensitive methods OR loads remote content |
| onReceivedSslError + proceed() | Always |

## Examples

True positives:
```kotlin
// Full attack surface: JS + file access + remote URL
val settings = webView.settings
settings.javaScriptEnabled = true
settings.allowFileAccess = true
webView.loadUrl(intent.getStringExtra("url") ?: "https://app.example.com")
```
```java
// SSL error bypass
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed(); // accepts any certificate
    }
});
```

False positives to skip:
```kotlin
// JS enabled but only loads hardcoded trusted local assets
settings.javaScriptEnabled = true
webView.loadUrl("file:///android_asset/help.html") // fully developer-controlled HTML
```

Report which specific settings are misconfigured, what the WebView loads (remote URL, deep-link controlled, local asset), and whether `addJavascriptInterface` exposes sensitive methods.
