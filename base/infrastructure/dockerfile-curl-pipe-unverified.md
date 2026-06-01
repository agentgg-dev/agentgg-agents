---
slug: dockerfile-curl-pipe-unverified
name: Dockerfile curl | sh Without Checksum
description: RUN curl | sh / wget | bash patterns that fetch and execute a script from the network without verifying a checksum or signature — supply-chain compromise risk.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    extensions:
      - Dockerfile
where:
  extensions:
    - Dockerfile
  filePatterns:
    - '**/Dockerfile'
    - '**/Dockerfile.*'
    - '**/Containerfile'
references:
  - CWE-494
  - 'OWASP-A06:2021'
---

You are reviewing Dockerfiles for `RUN` lines that download a script
or binary from the network and execute it without integrity
verification. If the upstream host is compromised (or the connection
is MitM'd in a setup with no TLS pinning), the build is compromised.

## What to look for

**Curl/wget piped into a shell:**
```dockerfile
RUN curl -sL https://example.com/install.sh | sh
RUN curl https://example.com/install.sh | bash
RUN wget -O - https://example.com/install.sh | sh
```

**Download then execute, no verification:**
```dockerfile
RUN curl -O https://example.com/installer.sh && sh installer.sh
RUN wget https://example.com/binary && chmod +x binary && ./binary
```

**`gpg --keyserver` for an unverified key, then trust:**
```dockerfile
RUN gpg --keyserver hkp://keys.gnupg.net --recv-keys ABC123
RUN curl -sL https://repo.example.com/key.gpg | apt-key add -
```

## Safe patterns

**Pin the script by checksum:**
```dockerfile
RUN curl -sL https://example.com/install.sh -o /tmp/install.sh \
 && echo "abc123def456...  /tmp/install.sh" | sha256sum -c - \
 && sh /tmp/install.sh
```

**Use the distribution's package manager with pinned versions
and signed repos:**
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends nodejs=20.10.0-1
```

**Use multi-stage build to fetch from an upstream image:**
```dockerfile
FROM tool@sha256:abc123 AS tool
COPY --from=tool /usr/local/bin/tool /usr/local/bin/tool
```

## True positive criteria

Flag when:
1. A `RUN` line contains `curl ... | sh|bash`, `wget ... | sh|bash`,
   or `curl ... | ash`, etc.
2. A `RUN` line downloads a script/binary and executes it without a
   subsequent checksum verification on the same line (or the
   immediately preceding/following lines combined with `&&`).
3. A `RUN` line trusts a key fetched ad-hoc (`apt-key add -` on a
   fetched URL).

## What to ignore

- `RUN` lines that include `sha256sum -c`, `shasum -c`, `gpg --verify`,
  or equivalent integrity checks on the downloaded artifact.
- Package manager calls with pinned versions from a signed repo
  (`apt-get install foo=1.2.3`, `apk add foo=1.2.3-r0`).
- Multi-stage builds copying from a digest-pinned upstream image.

## Examples

True positives:
```dockerfile
RUN curl -sL https://example.com/install.sh | bash
RUN wget -qO- https://get.example.com | sh
RUN curl https://nodejs.org/install.sh | sh
```

False positives to skip:
```dockerfile
RUN curl -sL https://example.com/installer.sh -o /tmp/i.sh \
 && echo "abc123...  /tmp/i.sh" | sha256sum -c - \
 && sh /tmp/i.sh

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.81.0-1ubuntu1.15
```
