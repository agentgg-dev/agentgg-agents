---
slug: rubygems-api-key
name: RubyGems API Key Exposure
description: 'Hardcoded RubyGems API keys (rubygems_ prefix + 48 hex) in source or config. Allow publishing, yanking, or managing gem ownership — a leaked key can push malicious gem versions for supply chain attacks.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '\brubygems_[a-zA-Z0-9]{48}\b'
      label: RubyGems API key (rubygems_ prefix + 48 chars)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded RubyGems API keys. RubyGems.org is the Ruby package registry — a leaked key can push malicious gem versions, enabling supply chain attacks.

## Token format

```
rubygems_<48 alphanumeric characters>
```

Keys are created at https://rubygems.org/profile/api_keys and can be scoped (push, yank, add owners).

## What a leaked key enables (depends on scopes)

**Push scope:** publish new gem versions — push malicious code that executes during `gem install` or via the gem itself. Supply chain attack vector.

**Yank scope:** remove existing gem versions — break downstream projects.

**Add owner scope:** add a new maintainer to any owned gem.

## True positive criteria

Flag when ALL hold:
1. Value matches `rubygems_[a-zA-Z0-9]{48}` exactly
2. String literal, not `${{ secrets.RUBYGEMS_API_KEY }}`
3. Not a placeholder

## Examples

True positive:
```yaml
env:
  RUBYGEMS_API_KEY: rubygems_<your_48_hex_chars_here>
```

Report which gems the account owns (if determinable) and whether the key is used in a CI release pipeline.
