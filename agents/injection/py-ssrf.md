---
slug: py-ssrf
name: Server-Side Request Forgery (Python)
description: 'Python HTTP client calls (requests, httpx, aiohttp, urllib) where the URL is user-controlled — allows probing internal networks, cloud metadata endpoints, or localhost services. Traces URL construction through config objects and helper functions to check for allowlist validation.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(requests|httpx)\.(get|post|put|delete|patch|head|request)\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: requests/httpx outbound call
      - regex: '(requests|httpx)\.(Session|Client|AsyncClient)\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: requests/httpx session construction
      - regex: 'aiohttp\.ClientSession\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: aiohttp client session
      - regex: 'urllib\.request\.urlopen\s*\(|\burlopen\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: urllib urlopen
      - regex: '\.(get|post|put|patch|delete)\s*\(\s*(url|target_url|endpoint|base_url|callback_url|webhook_url)\b'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/.venv/**'
          - '**/venv/**'
          - '**/site-packages/**'
        label: session call with a variable URL
where:
  extensions:
    - py
  excludePatterns:
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/.venv/**'
    - '**/venv/**'
    - '**/site-packages/**'
  preFilter:
    - regex: '(requests|httpx)\.(get|post|put|delete|patch|head|request)\s*\('
      label: requests/httpx outbound call
    - regex: 'aiohttp\.ClientSession\s*\('
      label: aiohttp client session
    - regex: 'urllib\.request\.urlopen\s*\(|\burlopen\s*\('
      label: urllib urlopen
    - regex: '\.(get|post|put|patch|delete)\s*\(\s*(url|target_url|endpoint|base_url|callback_url|webhook_url)\b'
      label: session call with variable URL
    - regex: '(requests|httpx)\.(get|post)\s*\(\s*f["'']'
      label: outbound call with an f-string URL
  maxFilesPerBatch: 5
references:
  - CWE-918
  - 'OWASP-A10:2021'
---

You are reviewing Python source code for Server-Side Request Forgery
(SSRF) — server-side HTTP calls whose URL is influenced by user input,
letting an attacker make the server issue requests to internal networks,
cloud metadata endpoints (169.254.169.254), or localhost services.

Python SSRF is structurally the same as Node.js SSRF but the APIs differ.
The URL usually arrives as a request parameter, a webhook or callback URL
stored per tenant, or a field in a config object the caller supplies.

**Config-derived base URLs:** In SDK and client-library code the base URL
is often not a request parameter at all. It is read from a config object,
an environment variable, or a token claim, then joined with a path and
passed to `requests`. That is still SSRF when the caller controls the
config value. A common shape is a client that decodes a JWT, reads an
issuer or environment claim, and picks the API host from it: the token
holder then controls where the SDK sends its authenticated requests.

**Cross-file analysis:** the URL is often passed through a helper. A view
accepts a `url` form field and calls a service function; the service
eventually calls `requests.get(url)`. Read the helper before deciding
whether validation occurs.

## What to look for

**requests:**
```python
target = request.args.get("url")
resp = requests.get(target, timeout=10)                 # fetches arbitrary URL
resp = requests.post(target, json=payload)
```

**httpx (sync and async):**
```python
url = body["callback_url"]
async with httpx.AsyncClient() as client:
    await client.get(url)
```

**aiohttp:**
```python
async with aiohttp.ClientSession() as session:
    async with session.get(user_supplied_url) as resp:
        return await resp.text()
```

**urllib (stdlib):**
```python
from urllib.request import urlopen
data = urlopen(request.GET["src"]).read()   # also accepts file:// and ftp://
```

**Base URL chosen from a token claim (SDK shape):**
```python
claims = jwt.decode(api_key, options={"verify_signature": False})
self.base_url = base_url or detect_base_url(claims.get("iss", ""))
# Missing: allowlist on the resulting host
self.session.post(f"{self.base_url}/api/v1/usage/ingest", json=event,
                  headers={"Authorization": f"Bearer {api_key}"})
```

## True positive criteria

Flag when ALL of the following hold:

1. A Python HTTP client constructs a request from a URL argument.
2. The URL argument is, transitively, caller-controlled: a request
   parameter, form or JSON body field, URL path segment, a token claim,
   a constructor/config argument, or a database record the user can write.
3. No host allowlist or private-IP block is applied before the request.
   A safe check validates the resolved hostname against a permitted set
   AND blocks private/link-local ranges: `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`, `fc00::/7`.

Note that `requests` follows redirects by default, so a permitted host
that returns a 302 to `169.254.169.254` defeats a host check applied only
to the original URL. An allowlist enforced once, before the call, is not
sufficient on its own.

## What to ignore

- URLs built from a fixed base with the user value used only as a path or
  query component, where the host is a server-controlled constant:
  ```python
  item_id = request.args["id"]
  requests.get(f"{FIXED_API_BASE}/items/{item_id}", timeout=5)
  ```
- Requests that go through a validated URL-checker helper whose body you
  have confirmed checks the host against an allowlist AND blocks private
  ranges.
- URLs sourced from operator-controlled configuration (environment
  variables, settings modules) where end users cannot write the value.
- Test code under `tests/`, `test_*.py`, `*_test.py`.
- Calls to a hardcoded literal URL.

## Examples

True positives:
```python
# Webhook delivery to a subscriber-authored callback
def deliver(subscription, payload):
    requests.post(subscription.callback_url, json=payload, timeout=5)

# Image proxy — classic metadata-endpoint SSRF
@app.route("/proxy")
def proxy():
    return requests.get(request.args["src"]).content

# SDK base URL derived from an unverified token claim
claims = jwt.decode(token, options={"verify_signature": False})
base = "https://api-staging.example.com" if "staging" in claims["iss"] else claims["aud"]
requests.post(base + "/ingest", json=event)
```

False positives to skip:
```python
# Fixed host, validated path segment
slug = request.args["slug"]
if not re.fullmatch(r"[a-z0-9-]+", slug):
    abort(400)
requests.get(f"{INTERNAL_API}/pages/{slug}", timeout=5)

# Host from operator configuration
requests.get(settings.UPSTREAM_URL + "/health", timeout=2)
```

If a caller-supplied string is used as, or forms the host portion of, a
URL passed to any Python HTTP client without host allowlisting and
private-range blocking, treat it as a finding.
