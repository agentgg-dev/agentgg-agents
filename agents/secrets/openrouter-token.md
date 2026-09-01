---
slug: openrouter-token
name: OpenRouter API Key Exposure
description: 'Hardcoded OpenRouter API keys committed to source. OpenRouter is an AI API gateway routing to Claude, GPT-4, Gemini, and other models — leaked keys enable unauthorized AI usage billed to the key owner.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '\bsk-or-[a-zA-Z0-9\-_]{20,}\b'
        in:
          - '**/*'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
          - '**/dist/**'
        label: OpenRouter API key (sk-or- prefix)
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
  preFilter:
    - regex: '\bsk-or-[a-zA-Z0-9\-_]{20,}\b'
      label: OpenRouter API key (sk-or- prefix)
    - regex: '(?i)OPENROUTER_API_KEY\s*=\s*[''"]?sk-or-'
      label: OPENROUTER_API_KEY variable assignment
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded OpenRouter API keys.

## Token format

OpenRouter API keys start with `sk-or-` followed by alphanumeric characters (similar format to OpenAI keys). Generated at openrouter.ai/keys.

## What a leaked key enables

- Make API calls to any AI model available on OpenRouter (Claude, GPT-4, Gemini, Llama, Mistral, etc.)
- All usage is billed to the key owner's OpenRouter account
- Depending on rate limits and credits, could result in significant unexpected charges
- Access to model responses that may be filtered through the key owner's configured safety settings

## True positive criteria

Flag when:
1. A string starting with `sk-or-` appears as a string literal
2. Not `process.env.OPENROUTER_API_KEY` or `${{ secrets.OPENROUTER_KEY }}`
3. Not in a comment showing an example key format

## What to ignore

- `sk-or-XXXX_HERE` or similar obvious placeholder values
- Environment variable references

Report: where the key appears (server-side API call, client-side browser code, CI config), and what model(s) the code is configured to call.
