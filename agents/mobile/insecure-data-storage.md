---
slug: insecure-data-storage
name: Insecure Local Storage of Sensitive Data (Mobile)
description: 'Mobile apps writing credentials, tokens, or PII to plaintext local storage (SharedPreferences, UserDefaults, plists, SQLite/Room, files) instead of EncryptedSharedPreferences / Keystore / Keychain. Follows the value from the secret source to the storage sink across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'getSharedPreferences\s*\(|PreferenceManager\.getDefaultSharedPreferences|MODE_WORLD_(READABLE|WRITEABLE)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Android SharedPreferences usage
      - regex: '(openOrCreateDatabase|SQLiteDatabase|Room\.databaseBuilder|getExternalFilesDir|getExternalStorageDirectory|openFileOutput)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Android local DB / file storage usage
      - regex: '(NSUserDefaults|UserDefaults|writeToFile|write\s*\(\s*to:|NSKeyedArchiver|kSecAttrAccessibleAlways|SecItemAdd|Keychain)'
        in:
          - '**/*.{swift,m,mm}'
        notIn:
          - '**/*Tests/**'
          - '**/*Test*'
        label: iOS UserDefaults / file / Keychain storage usage
  prompt: Run only if this is an Android or iOS app — confirm via the manifest (AndroidManifest.xml, Info.plist, build.gradle, Podfile, *.xcodeproj) and storage APIs in the code.
where:
  extensions:
    - java
    - kt
    - swift
    - m
    - mm
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/*_test.go'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/src/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - semgrepRule: mobile/mobile-storage
      label: Android SharedPreferences write or iOS UserDefaults / file write
    - regex: '\.edit\s*\(\s*\)|putString\s*\(|putInt\s*\(|getSharedPreferences\s*\('
      label: SharedPreferences write
    - regex: 'MODE_WORLD_(READABLE|WRITEABLE)'
      label: World-readable/writable SharedPreferences mode
    - regex: '(openOrCreateDatabase|SQLiteDatabase\.open|Room\.databaseBuilder)'
      label: Local SQLite / Room database
    - regex: '(getExternalFilesDir|getExternalStorageDirectory|Environment\.getExternalStoragePublicDirectory)'
      label: External storage write
    - regex: '(openFileOutput|FileOutputStream|\.writeText\s*\(|Files\.write)'
      label: File write
    - regex: '\b(NSUserDefaults|UserDefaults)\b.*\.set\s*\(|\.set\s*\(.*forKey:'
      label: iOS UserDefaults write
    - regex: '(writeToFile|\.write\s*\(\s*to:|NSKeyedArchiver\.archived)'
      label: iOS file / plist write
    - regex: 'kSecAttrAccessibleAlways'
      label: Keychain item accessible even when device locked
    - regex: '(password|passwd|token|secret|apiKey|api_key|credential|sessionId|session_token|ssn|creditCard|privateKey)'
      label: Sensitive value name near a storage call
references:
  - CWE-312
  - CWE-922
  - OWASP-Mobile-M9
---

You are reviewing Android (Java / Kotlin) and iOS / macOS (Swift /
Objective-C) source for sensitive data written to local storage in
plaintext (OWASP MASVS-STORAGE / M9). The attacker is anyone with
access to the device's storage: a malicious co-installed app reading a
world-readable file, an attacker with physical access or a backup, or
malware after a jailbreak / root. If credentials, tokens, or PII land
unencrypted in SharedPreferences, UserDefaults, a plist, an
unencrypted SQLite/Room DB, or a file on external storage, they read
it directly.

## Cross-file analysis

The secret and the storage call are usually a few hops apart. The
value comes from a login response, a token-refresh helper, or a
`User`/`Session` model in one file, and is persisted by a small
storage wrapper (`PrefsHelper`, `SecureStore`, `KeychainManager`,
`SessionRepository`) in another. Open both:

- Trace the field name (token, password, ssn, refresh_token) from where
  it is produced to where it is stored.
- Open the storage helper to see whether it actually encrypts.
  `EncryptedSharedPreferences`, Android Keystore, and iOS Keychain are
  safe; a class named `SecurePrefs` that wraps plain
  `SharedPreferences` is not.
- On Android, check the storage mode and location: external storage and
  `MODE_WORLD_READABLE/WRITEABLE` are world-accessible.

## What to look for

**Android — plaintext SharedPreferences for secrets:**
```kotlin
val prefs = getSharedPreferences("auth", Context.MODE_PRIVATE)
prefs.edit().putString("auth_token", token).apply()
prefs.edit().putString("password", password).apply()
```

**Android — world-readable/writable mode (deprecated, dangerous):**
```java
SharedPreferences p = getSharedPreferences("cfg", MODE_WORLD_READABLE);
```

**Android — unencrypted SQLite / Room or external-storage file:**
```kotlin
val db = openOrCreateDatabase("users.db", MODE_PRIVATE, null)
db.execSQL("INSERT INTO creds VALUES('$user','$password')")

File(getExternalFilesDir(null), "token.txt").writeText(token)
```

**iOS — secrets in UserDefaults or a plist:**
```swift
UserDefaults.standard.set(authToken, forKey: "authToken")
UserDefaults.standard.set(password, forKey: "password")
```
```objc
[[NSUserDefaults standardUserDefaults] setObject:token forKey:@"token"];
```

**iOS — file written without data protection:**
```swift
try token.write(to: fileURL, atomically: true, encoding: .utf8)
```
No `.completeFileProtection` / `NSFileProtectionComplete` attribute.

**iOS — Keychain with weak accessibility:**
```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,
    kSecValueData as String: tokenData
]
SecItemAdd(query as CFDictionary, nil)
```
`kSecAttrAccessibleAlways` keeps the item readable even when the device
is locked.

## True positive criteria

A finding is real when a sensitive value crosses the trust boundary
into device-readable plaintext storage. You must be able to state:

- The attacker: "a malicious co-installed app", "an attacker with a
  device backup", or "malware on a rooted/jailbroken device".
- The first-person capability: "I can read the auth token out of
  `shared_prefs/auth.xml`" / "out of the app's `NSUserDefaults` plist"
  / "off external storage" without the user's keys.
- The trust boundary: app-private encrypted storage (Keystore /
  Keychain / EncryptedSharedPreferences) vs. plaintext that other
  apps, backups, or filesystem access expose.

Flag when ALL hold:
1. The stored value is a credential, token, key, or PII (judge by name
   and origin, not by guesswork).
2. The sink is plaintext: plain `SharedPreferences`, `UserDefaults`,
   plist, unencrypted SQLite/Room, or a file (especially external
   storage or no file protection), OR Keychain with
   `kSecAttrAccessibleAlways`, OR `MODE_WORLD_READABLE/WRITEABLE`.
3. No encryption is applied to that value before storage.

The burden is on the code to prove the value is encrypted at rest.

## What to ignore

- `EncryptedSharedPreferences` (Jetpack Security) or values stored via
  the Android Keystore — these are correct.
- iOS Keychain with `kSecAttrAccessibleWhenUnlocked` /
  `...AfterFirstUnlock` (with or without `ThisDeviceOnly`) — correct.
- Files written with `NSFileProtectionComplete` /
  `.completeFileProtection`, or SQLCipher / encrypted Room databases.
- Non-sensitive data: UI preferences, theme, last-opened tab, feature
  flags, non-PII cache, analytics counters.
- Values that are already opaque/encrypted before they reach the store
  (e.g., a ciphertext blob or a hashed, non-reversible value).
- Test fixtures and sample apps under test directories.

## Examples

True positives:
```kotlin
getSharedPreferences("session", MODE_PRIVATE)
    .edit().putString("refresh_token", refreshToken).apply()
```
```swift
UserDefaults.standard.set(creditCardNumber, forKey: "card")
```
```swift
let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccessible as String: kSecAttrAccessibleAlways,
                        kSecValueData as String: pwData]
SecItemAdd(q as CFDictionary, nil)
```

False positives to skip:
```kotlin
val prefs = EncryptedSharedPreferences.create(
    "secret", masterKeyAlias, ctx,
    AES256_SIV, AES256_GCM)
prefs.edit().putString("auth_token", token).apply()
```
```swift
UserDefaults.standard.set("dark", forKey: "themeMode")
```
```swift
let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                        kSecValueData as String: tokenData]
SecItemAdd(q as CFDictionary, nil)
```
