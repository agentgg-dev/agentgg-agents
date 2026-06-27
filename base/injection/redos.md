---
slug: redos
name: Regular Expression Denial of Service (ReDoS)
description: 'User-supplied input passed directly to a regex compilation or execution function — allows an attacker to craft a catastrophically backtracking pattern that pins a thread or process and causes denial of service.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'new\s+RegExp\s*\('
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: new RegExp() call (JS/TS)
      - regex: 'Pattern\.compile\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{java,kt}'
          - '**/node_modules/**'
        label: Pattern.compile() call (Java/Kotlin)
      - regex: 're\.(compile|match|search|fullmatch|sub|subn|split|findall|finditer)\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.py'
          - '**/node_modules/**'
        label: re module call (Python)
      - regex: 'preg_(match|replace|split|grep|filter)\s*\('
        in:
          - '**/*.php'
        notIn:
          - '**/node_modules/**'
        label: preg_ call (PHP)
      - regex: 'Regexp\.(new|compile)\s*\(|\/\#\{'
        in:
          - '**/*.rb'
        notIn:
          - '**/*.test.rb'
          - '**/*.spec.rb'
          - '**/node_modules/**'
        label: Regexp.new or interpolated regex (Ruby)
      - regex: 'regexp\.(Compile|MustCompile|Match|MatchString)\s*\('
        in:
          - '**/*.go'
        notIn:
          - '**/*_test.go'
          - '**/node_modules/**'
        label: regexp call (Go)
      - regex: 'new\s+Regex\s*\('
        in:
          - '**/*.{cs,vb}'
        notIn:
          - '**/*.test.{cs,vb}'
          - '**/node_modules/**'
        label: new Regex() call (C#)
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
    - jsx
    - tsx
    - java
    - kt
    - py
    - php
    - rb
    - go
    - cs
    - vb
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs,java,kt,py,rb,cs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs,rb}'
    - '**/*_test.go'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: 'new\s+RegExp\s*\('
      label: new RegExp() call
    - regex: 'Pattern\.compile\s*\('
      label: Pattern.compile() call
    - regex: 're\.(compile|match|search|fullmatch|sub|subn|split|findall|finditer)\s*\('
      label: Python re module call
    - regex: 'preg_(match|replace|split|grep|filter)\s*\('
      label: PHP preg_ call
    - regex: 'Regexp\.(new|compile)\s*\(|\/\#\{'
      label: Ruby Regexp.new or interpolated regex
    - regex: 'regexp\.(Compile|MustCompile|Match|MatchString)\s*\('
      label: Go regexp call
    - regex: 'new\s+Regex\s*\('
      label: C# new Regex() call
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-1333
  - CWE-400
  - 'OWASP-A03:2021'
---

You are reviewing code for Regular Expression Denial of Service (ReDoS):
user-supplied input used as the pattern argument to a regex compilation
or execution function. An attacker can craft a pattern with catastrophic
backtracking (e.g. `(a+)+b`, `(a|a)+c`) that causes the regex engine to
explore an exponential number of paths, pinning a CPU thread for seconds
or minutes per request.

**Cross-file analysis:** the pattern value often originates in a request
handler, is passed through a service or utility layer, and reaches the
regex call several frames deep. Trace the argument back to its source to
confirm it crosses a trust boundary. Also check whether a timeout wrapper
or safe-regex validator intercepts it before the engine runs.

## The vulnerability

Most regex engines (Java, JavaScript V8 before linear-mode, Python, PHP
PCRE, Ruby) use backtracking. Certain pattern shapes cause the engine to
retry exponentially many partial matches before admitting failure:

```
Pattern: (a+)+b
Input:   aaaaaaaaaaaaaaaaac   ← no match at end forces full backtrack
```

A single request with a 30-character input can stall a thread for minutes.
If the pattern itself is user-supplied, the attacker controls both the
vulnerability and the trigger.

## What to look for

**JavaScript / TypeScript**
```js
// req.query.pattern passed to RegExp constructor
const pattern = req.query.filter;
const re = new RegExp(pattern);           // VULNERABLE
results = items.filter(i => re.test(i));

// String.match / replace with dynamic pattern
const re = new RegExp(req.body.search, req.body.flags);
```

**Java / Kotlin**
```java
// QueryParam value compiled directly
String userPattern = request.getParameter("pattern");
Pattern p = Pattern.compile(userPattern);  // VULNERABLE
Matcher m = p.matcher(input);

// String.matches() with user pattern
if (input.matches(userPattern)) { ... }   // VULNERABLE — compiles internally
```

**Python**
```python
# Flask / FastAPI — request param compiled or used directly
pattern = request.args.get('filter')
re.compile(pattern)          # VULNERABLE
re.match(pattern, value)     # VULNERABLE — also compiles internally
```

**PHP**
```php
// Pattern from request passed to preg_match
$pattern = $_GET['pattern'];
preg_match($pattern, $input, $matches);   // VULNERABLE
// Attacker can also inject PCRE modifiers: /pattern/e (eval)
```

**Ruby**
```ruby
# Regexp.new or interpolated regex from params
pattern = params[:filter]
re = Regexp.new(pattern)     # VULNERABLE
# or
re = /#{params[:search]}/    # VULNERABLE — interpolation into literal
```

**Go**
```go
// User-supplied pattern compiled
pattern := r.URL.Query().Get("filter")
re, err := regexp.Compile(pattern)        // VULNERABLE (though Go's engine
re := regexp.MustCompile(pattern)         // is RE2-based and linear-time —
// Note: Go's regexp package uses RE2 and is safe from ReDoS.
// Flag other languages; document Go as safe for this pattern.
```

**C#**
```csharp
string pattern = Request.Query["pattern"];
var re = new Regex(pattern);              // VULNERABLE
var re = new Regex(pattern, RegexOptions.Compiled); // same risk
// .NET 7+ has a timeout option — check if it is set
var re = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(200)); // safe
```

## True positive criteria

Flag when ALL of the following hold:

1. A regex compilation or execution call is present: `new RegExp()`,
   `Pattern.compile()`, `re.compile()` / `re.match()`, `preg_match()`,
   `Regexp.new()`, `new Regex()`.
2. The pattern argument originates from user-controlled input: a request
   query param, path param, body field, header, or any value that
   crosses a network boundary.
3. No safe interception is applied before the engine runs:
   - No allowlist of permitted patterns
   - No safe-regex / vuln-regex validator (e.g. `safe-regex` npm package,
     `re2` binding, OWASP validation)
   - For C# `Regex`: no `matchTimeout` set
   - For Java: no `Pattern.compile` timeout or `AppendReplacement` guard
   - For PHP: no PCRE backtrack limit set via `pcre.backtrack_limit`

## What to ignore

- **Go**: the `regexp` package uses RE2 (linear time). User-supplied
  patterns in Go are safe from ReDoS — flag only the injection of
  modifiers or the use of a non-RE2 library.
- Regex patterns loaded from the server's own config files or hardcoded
  constants — the attacker cannot influence them.
- Patterns validated against an allowlist before use.
- `new RegExp(str)` where `str` is always a hardcoded string literal
  or a controlled template with no user-supplied components.
- Test files constructing regexes from test-fixture strings.

## Examples

True positives:
```js
// Express — filter param compiled directly
app.get('/search', (req, res) => {
  const re = new RegExp(req.query.q);       // user controls pattern
  res.json(data.filter(x => re.test(x)));
});
```
```java
// Spring controller — path variable used as pattern
@GetMapping("/filter/{pattern}")
public List<String> filter(@PathVariable String pattern) {
  return items.stream()
    .filter(s -> s.matches(pattern))         // VULNERABLE
    .collect(toList());
}
```
```python
# FastAPI — query param passed to re.compile
@app.get("/search")
def search(pattern: str):
    compiled = re.compile(pattern)           # VULNERABLE
    return [x for x in data if compiled.match(x)]
```

False positives to skip:
```js
// Hardcoded pattern — attacker cannot influence it
const re = new RegExp('^[a-z]+$');

// safe-regex check applied first
const safeRegex = require('safe-regex');
const pat = req.query.filter;
if (!safeRegex(pat)) return res.status(400).send('unsafe pattern');
const re = new RegExp(pat);
```
```csharp
// Timeout set — bounded execution time
var re = new Regex(pattern, RegexOptions.None,
                   TimeSpan.FromMilliseconds(250));
```
