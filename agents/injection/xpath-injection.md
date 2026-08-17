---
slug: xpath-injection
name: XPath Injection
description: 'User input concatenated or interpolated into an XPath query string — letting an attacker alter the query to bypass auth or exfiltrate XML data. Sinks: Java XPath.compile/evaluate, .NET SelectNodes/SelectSingleNode, Python lxml .xpath(), PHP DOMXPath->query. Traces the query string back to request input.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.(compile|evaluate)\s*\([^)]*(\+|String\.format)|XPathExpression'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/tests/**'
          - '**/*_test.{java,kt}'
        label: Java XPath.compile/evaluate with concatenation
      - regex: '\.(SelectNodes|SelectSingleNode)\s*\([^)]*(\+|\$"|String\.Format)'
        in:
          - '**/*.cs'
        notIn:
          - '**/tests/**'
        label: .NET SelectNodes/SelectSingleNode with interpolation
      - regex: '\.xpath\s*\(\s*(f[''"]|[''"][^''"]*[''"]\s*[%+]|[^)]*\+|[^)]*\.format\s*\()'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
        label: Python lxml .xpath() with f-string/concat/format
      - regex: '->query\s*\(\s*(["''][^"'']*["'']\s*\.|[^)]*\$)'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
        label: PHP DOMXPath->query with variable/concat
where:
  extensions:
    - java
    - kt
    - cs
    - py
    - php
  excludePatterns:
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: '\.(compile|evaluate)\s*\([^)]*(\+|String\.format)|XPathExpression'
      label: Java XPath.compile/evaluate with concatenation
    - regex: '\.(SelectNodes|SelectSingleNode)\s*\([^)]*(\+|\$"|String\.Format)'
      label: .NET SelectNodes/SelectSingleNode with interpolation
    - regex: '\.xpath\s*\(\s*(f[''"]|[''"][^''"]*[''"]\s*[%+]|[^)]*\+|[^)]*\.format\s*\()'
      label: Python lxml .xpath() with f-string/concat/format
    - regex: '->query\s*\(\s*(["''][^"'']*["'']\s*\.|[^)]*\$)'
      label: PHP DOMXPath->query with variable/concat
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-643
---

You are reviewing source for XPath injection — user-controlled input
concatenated or interpolated into an XPath query string. Like SQL
injection, an attacker who controls part of the query can break out of
the intended predicate and change which nodes are selected: bypassing an
XML-backed login (`' or '1'='1`), or walking the document to read other
users' data.

**Cross-file analysis:** the XPath string is often built in a DAO/helper
a few hops from the request handler. Trace each interpolated value back
to its origin — a variable named `user` in the query may be
`req.getParameter("user")`. Open the caller to confirm whether the
value crosses a trust boundary before it lands in the query.

## What to look for

- Java: `xpath.compile("/users/user[name='" + name + "']")` then
  `.evaluate(...)`, or building the expression with `String.format`:
  ```java
  String q = "/users/user[@name='" + req.getParameter("u") + "']";
  XPathExpression e = xpath.compile(q);
  ```
- .NET: `doc.SelectNodes("/users/user[@name='" + name + "']")` /
  `SelectSingleNode`, including `$"..."` interpolation and
  `String.Format`:
  ```csharp
  doc.SelectSingleNode($"//user[name/text()='{Request["u"]}']");
  ```
- Python lxml: `tree.xpath(f"//user[@name='{name}']")` or with `%`,
  `.format`, or `+` concatenation:
  ```python
  tree.xpath("//user[@name='" + request.args["u"] + "']")
  ```
- PHP: `$xpath->query("//user[@name='" . $_GET['u'] . "']")`:
  ```php
  $nodes = $xpath->query("//user[@pass='" . $_POST['pw'] . "']");
  ```

## True positive criteria

A finding is real when a request-derived value is concatenated /
interpolated / formatted into the string passed to an XPath
compile/evaluate/query call, with no parameterization (variable
binding) and no strict input validation in between.

You must be able to say: "I am an unauthenticated client. I send
`u=' or '1'='1` (or a quote to break the predicate); the XPath query
re-shapes to select nodes I shouldn't see, bypassing the login / leaking
records." Name the attacker and the trust boundary (the request param).
The burden is on the code to prove it uses XPath variables / parameter
binding (`XPathVariableResolver`, `setXPathVariable`,
`$xpath->query` with bound variables, or lxml `xpath(..., name=value)`)
or strictly validates the value.

## What to ignore

- Queries that use XPath variables / parameter binding instead of
  string building:
  ```java
  xpath.setXPathVariableResolver(...);
  xpath.compile("//user[@name=$name]");
  ```
  ```python
  tree.xpath("//user[@name=$n]", n=name)
  ```
- Fully constant XPath expressions with no interpolation.
- Interpolated values that are server-derived constants or already
  validated against a strict allowlist (e.g. matched `^[a-z0-9_]+$`)
  before use.
- Values numerically cast / bounded (an integer index) such that no
  XPath metacharacter can survive.

## Examples

True positives:
```java
String q = "/users/user[name='" + login + "' and pass='" + pw + "']";
Boolean ok = (Boolean) xpath.evaluate(q, doc, XPathConstants.BOOLEAN);
```
```csharp
var node = doc.SelectSingleNode("//user[@id='" + Request["id"] + "']");
```
```python
nodes = tree.xpath("//user[@name='%s']" % request.args["u"])
```
```php
$r = $xpath->query("//account[owner='" . $_GET['o'] . "']");
```

False positives to skip:
```java
xpath.setXPathVariableResolver(v -> v.getLocalPart().equals("name") ? login : null);
xpath.compile("//user[name=$name]").evaluate(doc, XPathConstants.NODE);
```
```python
tree.xpath("//user[@name=$n]", n=request.args["u"])
```
```csharp
var nodes = doc.SelectNodes("//user[@active='true']");
```

If a request value is string-built into an XPath query with no binding
or strict validation on the path, treat it as a finding — the burden is
on the code to demonstrate the value can't alter the query structure.
