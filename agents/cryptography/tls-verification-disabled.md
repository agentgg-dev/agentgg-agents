---
slug: tls-verification-disabled
name: TLS Certificate Verification Disabled
description: 'Client code that disables TLS/SSL certificate or hostname verification (requests verify=False, Node rejectUnauthorized:false, Go InsecureSkipVerify, trust-all TrustManager, CURLOPT_SSL_VERIFYPEER=false, .NET ServerCertificateValidationCallback returning true), enabling man-in-the-middle attacks. Traces helper/config that sets the flag.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'verify\s*=\s*False|_create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/vendor/**'
        label: Python TLS verification disabled
      - regex: 'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Node TLS verification disabled
      - regex: 'InsecureSkipVerify\s*:\s*true'
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/vendor/**'
        label: Go InsecureSkipVerify true
      - regex: 'CURLOPT_SSL_VERIFY(PEER|HOST)\s*,?\s*(=>|,)?\s*(false|0)|setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|checkServerTrusted'
        in:
          - '**/*.php'
          - '**/*.java'
          - '**/*.kt'
        notIn:
          - '**/tests/**'
          - '**/vendor/**'
        label: PHP/Java TLS verification disabled
      - regex: 'ServerCertificateValidationCallback\s*(\+?=)|ServerCertificateCustomValidationCallback\s*='
        in:
          - '**/*.cs'
        notIn:
          - '**/tests/**'
        label: .NET certificate validation override
where:
  extensions:
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - go
    - php
    - java
    - kt
    - cs
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
  preFilter:
    - regex: 'verify\s*=\s*False'
      label: Python requests verify=False
    - regex: '_create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False'
      label: Python unverified SSL context / CERT_NONE
    - regex: 'rejectUnauthorized\s*:\s*false'
      label: 'Node rejectUnauthorized: false'
    - regex: 'NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[''"]?0'
      label: Node NODE_TLS_REJECT_UNAUTHORIZED=0
    - regex: 'InsecureSkipVerify\s*:\s*true'
      label: Go tls.Config InsecureSkipVerify true
    - regex: 'CURLOPT_SSL_VERIFY(PEER|HOST)\s*(=>|,)\s*(false|0)'
      label: PHP CURLOPT_SSL_VERIFYPEER/HOST disabled
    - regex: 'setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER'
      label: Java ALLOW_ALL hostname verifier
    - regex: 'checkServerTrusted\s*\([^)]*\)\s*\{?\s*(\}|return|$)|TrustAllCerts|X509TrustManager'
      label: Java trust-all TrustManager
    - regex: 'ServerCertificateValidationCallback\s*(\+?=)|ServerCertificateCustomValidationCallback\s*='
      label: .NET certificate validation override
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-295
  - 'OWASP-A02:2021'
---

You are reviewing client-side network code for disabled TLS/SSL
certificate or hostname verification — when verification is off, an
on-path attacker (rogue Wi-Fi, compromised router, malicious proxy,
ARP/DNS spoofer) can present any certificate and silently
man-in-the-middle the connection, reading and modifying traffic to
the server. The trust boundary is the network between this client
and the remote host.

**Cross-file analysis:** the flag is often hidden in a shared HTTP
client factory, a base API wrapper, or environment configuration a
few hops from the call site. Trace a `session`/`client`/`httpClient`
object back to where its TLS options are set. A custom
`TrustManager`/`HostnameVerifier`/validation callback may live in a
separate file and be installed globally (e.g.
`HttpsURLConnection.setDefaultSSLSocketFactory`,
`ServicePointManager.ServerCertificateValidationCallback`) — a
single global install affects every connection in the process.

## What to look for

**Python (`requests`, `urllib`, `httpx`, raw `ssl`):**
```py
requests.get(url, verify=False)
ctx = ssl._create_unverified_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
httpx.Client(verify=False)
```

**Node (`https`, `axios`, `node-fetch`, `tls`):**
```js
new https.Agent({ rejectUnauthorized: false })
axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) })
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
```

**Go (`crypto/tls`, `net/http`):**
```go
tr := &http.Transport{ TLSClientConfig: &tls.Config{ InsecureSkipVerify: true } }
```

**Java/Kotlin (trust-all `TrustManager` / allow-all hostname):**
```java
new X509TrustManager() {
  public void checkServerTrusted(X509Certificate[] c, String a) {}  // empty = trust all
}
conn.setHostnameVerifier((hostname, session) -> true);
HttpsURLConnection.setDefaultHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
```

**PHP (cURL):**
```php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
```

**.NET (`HttpClient` / `ServicePointManager`):**
```csharp
ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, err) => true;
handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
```

## True positive criteria

Flag when verification is disabled on a client connection that
reaches a real remote host. You should be able to say: "An attacker
on the network path between this client and `<host>` can present a
self-signed/forged certificate; because verification is disabled,
the client accepts it and the attacker reads/alters the traffic."
The trust boundary is the untrusted network. Burden of proof is on
the code to show the connection is not security-sensitive (and
"it's only internal" is not sufficient — internal networks are
attacker-reachable too).

A custom callback / `TrustManager` is a finding when it
unconditionally returns success (returns `true`, throws nothing,
empty `checkServerTrusted`) regardless of the certificate.

## What to ignore

- Test files, fixtures, and integration tests that hit a local test
  server with a self-signed cert (`localhost`, `127.0.0.1`,
  `*.local`, a docker service name) — clearly scoped to tests.
- A callback that actually validates: pins a specific certificate /
  public key, checks `chain`/`errors == None`, or compares the
  thumbprint to an expected value. That is certificate pinning, not
  disabled verification.
- `verify="/path/to/ca-bundle.pem"` or a custom CA bundle / truststore
  — that strengthens verification, not disables it.
- Code paths gated to a dev-only branch where the flag is
  unreachable in production (confirm the gate is real, e.g.
  `if (env === "development")` and the value is never the default).
- Disabling verification toward `localhost`/loopback dev tooling
  with no production reach.

Do not let a `# nosec` / `// nolint` comment or a vague "internal
only" justification override a finding on a production client.

## Examples

True positives:
```py
resp = requests.post("https://api.partner.com/pay", json=d, verify=False)
```
```go
client := &http.Client{Transport: &http.Transport{
  TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
resp, _ := client.Get("https://payments.example.com/")
```
```csharp
ServicePointManager.ServerCertificateValidationCallback =
  (sender, cert, chain, errors) => true;
```

False positives to skip:
```py
def test_self_signed():
    requests.get("https://localhost:8443/health", verify=False)
```
```csharp
handler.ServerCertificateCustomValidationCallback = (m, cert, chain, errs) =>
    cert.GetCertHashString() == PinnedThumbprint;
```
