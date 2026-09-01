---
slug: pii-government-id
name: Government ID / SSN in Source Code or Config
description: 'US Social Security Numbers, national ID numbers, or other government-issued identifiers present as string literals in source code, test data, or committed config files. A compliance violation (GDPR, CCPA, HIPAA) even for synthetic-looking values in production code paths.'
version: 0.1.0
author: agentgg
noiseTier: normal
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
    - regex: '(?:(?!000|666|9\d{2})\d{3})-(?!00)\d{2}-(?!0000)\d{4}'
      label: US Social Security Number (ddd-dd-dddd, excludes obvious invalids)
    - regex: '(?i)(?:ssn|social.?security|national_id|sin_number|social_insurance|nino|passport_number|driver.?licen[sc]e)\s*[=:]\s*[''"]?[A-Z0-9\-]{6,20}'
      label: Government ID in named variable (ssn, national_id, passport, etc.)
    - regex: '(?i)(?:individual_taxpayer|itin)\s*[=:]\s*[''"]?9\d{2}[78]\d{6}'
      label: US Individual Taxpayer Identification Number (ITIN)
references:
  - CWE-312
  - CWE-359
  - 'OWASP-A02:2021'
---

You are reviewing source code, test fixtures, and config files for government-issued ID numbers. These patterns have moderate false-positive rates — context determines whether each match is a real finding.

## Patterns to evaluate

**US SSN (`ddd-dd-dddd`):** three digits, dash, two digits, dash, four digits. The preFilter excludes obvious invalids (000, 666, 9xx prefixes which are ITINs not SSNs). Still high false-positive rate — evaluate context.

**Variable names indicating government IDs:** `ssn`, `social_security_number`, `national_id`, `sin_number`, `nino`, `passport_number`, `driver_license`. If a variable with one of these names contains an ID-shaped value, that is a strong signal.

**ITIN (Individual Taxpayer Identification Number):** `9xx-7x-xxxx` or `9xx-8x-xxxx` format. Used for tax filing by non-citizens.

## True positive criteria

Flag when EITHER holds:
1. The pattern matches AND the surrounding context relates to user data (name, date of birth, address, medical or employment records, tax data)
2. A variable named `ssn`, `social_security`, `national_id`, or equivalent contains a digit string in the ID format

Flag at critical severity:
- In a data migration or seed script with multiple records
- In a CSV/JSON file with real-looking personal data alongside the ID

Flag at lower severity:
- Single synthetic-looking test value in a unit test

## What to ignore

- SSN-format strings in clearly unrelated contexts: `version = '123-45-6789'`, internal record IDs
- Known fake/test SSNs: `000-00-0000`, `123-45-6789`, `999-99-9999`, `987-65-4321`
- Regex patterns for SSN validation in validation library code — the regex itself is not an SSN
- Documentation explaining the SSN format with an example value clearly marked as such

## Examples

Critical (data seed with real-looking records):
```python
users = [
    {'name': 'John Smith', 'ssn': '456-78-9012', 'dob': '1985-03-15', 'email': 'john@smith.com'},
]
```

Lower severity (synthetic test value):
```python
def test_ssn_validation():
    assert validate_ssn('078-05-1120') == True  # known SSN from test datasets
```

Not an SSN:
```python
record_id = '123-45-6789'  # internal record ID, no user data context
```

Report: the format found (SSN vs ITIN vs other), whether it appears with other PII, the file type, and approximate record count if in a data file.
