---
slug: xxe
name: XML External Entity (XXE)
description: 'XML parsers configured to resolve external entities or DTDs, allowing attacker-controlled XML to read local files, perform SSRF, or trigger entity-expansion DoS (billion laughs).'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - ts
      - tsx
      - js
      - jsx
      - mjs
      - cjs
      - py
      - rb
      - go
      - rs
      - php
      - java
      - kt
      - cs
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - rb
    - go
    - rs
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
    - '**/build/**'
    - '**/.next/**'
references:
  - CWE-611
  - CWE-776
  - 'OWASP-A05:2021'
---

You are reviewing source code for XML External Entity (XXE) — XML
parsers that resolve `<!ENTITY>` references to external resources or
expand nested entities without limit, exploited by uploading XML that
references `file:///etc/passwd`, an internal URL (SSRF), or a recursive
entity chain (DoS).

The defining mistake is parsing untrusted XML with a parser whose
external-entity / DTD handling is left at its unsafe default or
explicitly enabled.

## What to look for

**Node.js — libxmljs / libxmljs2:**
```ts
libxml.parseXml(data, { noent: true });          // noent:true expands entities → XXE
libxmljs.parseXmlString(xml, { noent: true });
```
The `noent` option name is misleading — `true` means *substitute*
entities, which is the unsafe mode.

**Node.js — fast-xml-parser:**
```ts
new XMLParser({ processEntities: true, htmlEntities: false });
```
Custom DTD entities can be defined when `processEntities` is on.

**Node.js — xml2js:** Generally safe by default but flag any explicit
`explicitChildren: true` combined with `attrkey`/`charkey` that
preserves doctype.

**Python — lxml / xml.etree / xml.sax / xml.dom.minidom:**
```python
etree.parse(file)                                  # default resolves entities
etree.XMLParser(resolve_entities=True, no_network=False)
xml.sax.make_parser()                              # no feature_external_ges disable
minidom.parseString(data)                          # no defusedxml
```

**Java — DocumentBuilderFactory / SAXParserFactory / XMLReader:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// No setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
// No setFeature("http://xml.org/sax/features/external-general-entities", false)
DocumentBuilder db = dbf.newDocumentBuilder();
db.parse(input);
```

**PHP — libxml:**
```php
libxml_disable_entity_loader(false);   // explicitly enables external entities
$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT | LIBXML_DTDLOAD);
```

**.NET — XmlReaderSettings / XmlDocument:**
```cs
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver();   // wires up external resolution
doc.LoadXml(xml);
```

**Go — encoding/xml:** Standard library does NOT resolve external
entities. Flag third-party packages that do (e.g., custom DTD handlers).

**Universal smell:** A handler that accepts an XML file/string from a
request, parses it with one of the above APIs, and uses the parsed
result. If no hardening is visible, it's a candidate.

## True positive criteria

Flag when ALL of the following hold:

1. XML data crossing a trust boundary (uploaded file, request body,
   external API response) is fed to a parser.
2. The parser is configured to resolve external entities or DTDs —
   either by explicit flag (`noent: true`, `resolve_entities=True`,
   `XmlResolver = new XmlUrlResolver()`, `LIBXML_NOENT`) OR by leaving
   the unsafe default (DocumentBuilderFactory without
   `disallow-doctype-decl`, lxml without `resolve_entities=False`).
3. No `defusedxml`-equivalent wrapper, DTD-disabling feature, or
   entity-expansion limit is applied.

## What to ignore

- Parsers explicitly hardened: `defusedxml.ElementTree.parse(...)`,
  `XMLParser(resolve_entities=False)`, `libxml_disable_entity_loader(true)`,
  DocumentBuilderFactory with the disallow-doctype-decl feature set,
  `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`.
- XML data that originates from the application itself (config files,
  fixtures, generated documents).
- Test files / fixtures.
- Parsers used purely to *serialize* (output) XML — XXE is an input-side
  bug.

## Examples

True positives:
```ts
// libxmljs with noent — classic XXE
const doc = libxml.parseXml(req.file.buffer.toString(), { noent: true });

// Python lxml leaving defaults
import lxml.etree as ET
tree = ET.parse(uploaded_path)

// Java DocumentBuilder unhardened
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document d = db.parse(req.getInputStream());
```

False positives to skip:
```python
# defusedxml — entity expansion disabled
from defusedxml import ElementTree as ET
tree = ET.parse(uploaded_path)
```
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
```ts
// fast-xml-parser with processEntities disabled — safe
new XMLParser({ processEntities: false });
```

When the language/library is known-safe-by-default (e.g., Go's
`encoding/xml`), don't flag absence of hardening.
