---
slug: ios-url-scheme
name: iOS Custom URL Scheme Handler Without Validation
description: iOS / macOS custom URL scheme handler (application(_:open:options:)) accepting parameters without validation — deeplink parameter injection.
version: 0.1.0
author: agentgg
mode: file
tech: [ios]
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{swift,m,mm}"
  - "**/Info.plist"
references:
  - CWE-20
  - OWASP-Mobile-M1
---

You are reviewing iOS / macOS source code that handles custom URL
schemes (deeplinks) for missing input validation. The URL scheme is
the entry point any app — or web page — on the device can use to
launch your app and pass parameters; if the handler trusts the
parameters, the calling app can drive your app's state.

## What to look for

**`application(_:open:options:)` reading parameters without validation:**
```swift
func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    let token = URLComponents(url: url, resolvingAgainstBaseURL: false)?
        .queryItems?.first(where: { $0.name == "token" })?.value
    if let token = token {
        signIn(with: token)
    }
    return true
}
```
Any app can launch yours with `yourapp://login?token=...`.

**`SceneDelegate.scene(_:openURLContexts:)` with same issue.**

**Universal Links (Associated Domains) — host validated by OS but
path parameters still untrusted:**
```swift
func application(_ app: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: ...) -> Bool {
    if userActivity.activityType == NSUserActivityTypeBrowsingWeb {
        let url = userActivity.webpageURL!
        openDocument(at: url.path)   // path is web-controlled
    }
}
```

**Info.plist declares the URL scheme:**
```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>myapp</string></array>
  </dict>
</array>
```
The scheme being declared makes the app responsive to that URL —
review the handler.

## Required validation

For sensitive operations triggered by deeplinks:
- Verify the source app is trusted (check `options[.sourceApplication]`).
- Validate every parameter (token format, ID shape, etc.).
- Prefer Universal Links over custom schemes — they verify the
  associated domain, so only your domain can launch the link.
- Don't auto-execute sensitive actions on URL open; require a user
  confirmation in the UI.

## True positive criteria

Flag when:
1. `application(_:open:options:)` or `scene(_:openURLContexts:)` is
   implemented.
2. The handler reads query parameters / path components from the
   URL.
3. The handler performs a sensitive action (sign-in with token,
   transfer money, change settings) without user confirmation and
   without source-app verification.

## What to ignore

- Handlers that simply navigate to a screen and don't perform
  side-effecting actions until the user confirms.
- Handlers that strictly validate input shape before use.
- Test files.

## Examples

True positives:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    if url.host == "auth" {
        let token = url.queryParameters["token"]
        signInWithToken(token!)    // no validation, no user confirm
        return true
    }
    return false
}
```

False positives to skip:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    guard url.host == "auth",
          let token = url.queryParameters["token"],
          isValidJWTFormat(token) else { return false }

    // Navigate to login screen showing the token, require user tap to sign in
    navigateToConfirmSignIn(with: token)
    return true
}
```
