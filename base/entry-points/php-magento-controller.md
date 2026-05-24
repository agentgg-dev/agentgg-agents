---
slug: php-magento-controller
name: Magento Controller Entry Points
description: Locates Magento 2 controllers, webapi.xml routes, and request param accessors via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [magento]
noiseTier: noisy
filePatterns:
  - "**/Controller/**/*.php"
  - "**/etc/webapi.xml"
excludePatterns:
  - "**/tests/**"
  - "**/vendor/**"
  - "**/dev/tests/**"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "extends\\s+\\\\?Magento\\\\Framework\\\\App\\\\Action\\\\Action\\b"
    label: "Magento Action subclass"
  - regex: "implements\\s+\\\\?Magento\\\\Framework\\\\App\\\\(?:Action\\\\)?HttpGetActionInterface"
    label: "HttpGetActionInterface implementation"
  - regex: "<route\\s+url=[\"'][^\"']+[\"']\\s+method=[\"'][A-Z]+[\"']"
    label: "webapi.xml <route> declaration"
  - regex: "\\$this->getRequest\\s*\\(\\s*\\)->getParam\\s*\\("
    label: "request param accessor"
references:
  - CWE-862
  - CWE-20
---

Regex-only rule (no LLM). Locates Magento 2 controllers, webapi.xml
route declarations, and request param accessors.

Gated on `tech: [magento]` — only runs when `fingerprint(root)`
detects Magento.

## What this finds

- Action subclasses (`extends \Magento\Framework\App\Action\Action`)
- `HttpGetActionInterface` implementations
- `<route url="..." method="...">` declarations in `webapi.xml`
- `$this->getRequest()->getParam(...)` accessors

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
