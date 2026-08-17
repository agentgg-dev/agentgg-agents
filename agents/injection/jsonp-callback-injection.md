---
slug: jsonp-callback-injection
name: JSONP Callback Parameter Injection
description: 'JSONP callback or function-name parameter reflected into a JavaScript response body without allowlist validation — allows arbitrary script injection when the response is loaded via a script tag.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'query\.(callback|jsonp)|query\[.*(callback|jsonp)|args\.get\(.*(callback|jsonp)|_GET\[.*(callback|jsonp)|params\[.*(callback|jsonp)|getParameter\(.*(callback|jsonp)|options\.jsonp\(\)|set_jsonp\('
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
          - '**/*.{py,php,rb,go,java,cs}'
          - '**/*.{cc,cpp,h,hpp}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: JSONP callback parameter read from request
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
    - jsx
    - tsx
    - py
    - php
    - rb
    - go
    - java
    - cs
    - cc
    - cpp
    - h
    - hpp
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: 'query\.(callback|jsonp)|query\[.*(callback|jsonp)|args\.get\(.*(callback|jsonp)'
      label: JSONP callback from request query (JS/Python)
    - regex: '_GET\[.*(callback|jsonp)|_REQUEST\[.*(callback|jsonp)'
      label: JSONP callback from request query (PHP)
    - regex: 'params\[.*(callback|jsonp)|getParameter\(.*(callback|jsonp)'
      label: JSONP callback from request query (Ruby/Java)
    - regex: 'options\.jsonp\(\)|set_jsonp\(|\.get<[^>]*>\s*\(\s*"jsonp"'
      label: JSONP callback access (C++)
    - regex: 'application/javascript|text/javascript'
      label: JavaScript content-type response
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-79
  - CWE-116
  - 'OWASP-A03:2021'
---

You are reviewing server-side code for JSONP callback injection: a
reflected XSS variant where a user-supplied callback function name is
written directly into a JavaScript response body without validation.

**Cross-file analysis:** the callback value is often extracted in a
middleware or options parser, stored in a config/options struct, and
then used later in a response formatter. Trace from the point of
extraction through to wherever the response body is assembled. The
validation (or lack of it) may be in either location.

## The vulnerability

JSONP is a legacy technique for cross-origin data access. The server
wraps a JSON payload in a function call:

```
callbackName({"data": ...})
```

The client supplies the callback name via a query parameter (`?callback=myFn`
or `?jsonp=myFn`). When the server reflects this value without validation,
an attacker can inject arbitrary JavaScript:

```
GET /api/data?callback=alert(document.cookie)//
```

Response (Content-Type: application/javascript):
```js
alert(document.cookie)//({"data": ...})
```

If any page loads this URL via `<script src="...">`, the injected code
executes in the victim's browser in the origin of the server.

A valid callback name is an identifier: letters, digits, `_`, `$`,
and `.` only (e.g. `jQuery.handle`, `myNamespace.cb`). Anything else
is injection.

## What to look for

**Node.js / TypeScript**
```js
const callback = req.query.callback; // or req.query.jsonp
res.type('application/javascript');
res.send(`${callback}(${JSON.stringify(data)})`); // VULNERABLE
```

**Python (Flask / FastAPI / Django)**
```python
callback = request.args.get('callback')
return Response(f"{callback}({json.dumps(data)})",
                mimetype='application/javascript')  # VULNERABLE
```

**PHP**
```php
$callback = $_GET['callback'];
header('Content-Type: application/javascript');
echo $callback . '(' . json_encode($data) . ')';  // VULNERABLE
```

**Ruby on Rails**
```ruby
callback = params[:callback]
render plain: "#{callback}(#{data.to_json})",
       content_type: 'application/javascript'  # VULNERABLE
```

**Go**
```go
callback := c.Query("callback")
c.Header("Content-Type", "application/javascript")
c.String(http.StatusOK, callback+"("+string(jsonBytes)+")")  // VULNERABLE
```

**C++ (custom HTTP server)**
```cpp
std::string jsonp = options.jsonp(); // extracted from request param
// ... later in response formatter ...
worker.format(jsonp + "(" + body + ")");  // VULNERABLE
```

## True positive criteria

Flag when ALL of the following hold:

1. A query/request parameter named `callback`, `jsonp`, or a
   functional equivalent is read from the incoming request.
2. The value (or a string derived from it) is placed into the HTTP
   response body as part of a JavaScript function call wrapper.
3. The response has Content-Type `application/javascript`,
   `text/javascript`, or the endpoint is documented as a JSONP
   endpoint.
4. No allowlist validation is applied to the callback name before
   it is written into the response. Adequate validation is a strict
   regex or allowlist that permits only valid JavaScript identifiers
   (letters, digits, `_`, `$`, `.`) — not a blacklist and not a
   length check alone.

## What to ignore

- Callback values validated against a strict allowlist or identifier
  regex (e.g. `^[a-zA-Z_$][a-zA-Z0-9_$.]*$`) before use.
- Responses with Content-Type `application/json` — these are not
  JSONP and the callback is not executed by the browser.
- Client-side JavaScript that constructs a JSONP `<script>` tag —
  the injection risk is on the server that serves the response, not
  the client that requests it.
- Test or mock handlers that only run in controlled test environments.

## Examples

True positives:
```js
// Express — no validation on callback name
const cb = req.query.callback ?? 'callback';
res.send(`${cb}(${JSON.stringify(result)})`);

// Go — callback concatenated directly
jsonpCallback := r.URL.Query().Get("jsonp")
fmt.Fprintf(w, "%s(%s)", jsonpCallback, jsonBytes)
```

False positives to skip:
```js
// Strict identifier validation applied
const cb = req.query.callback;
if (!/^[a-zA-Z_$][a-zA-Z0-9_$.]*$/.test(cb)) {
  return res.status(400).json({ error: 'invalid callback' });
}
res.send(`${cb}(${JSON.stringify(result)})`);
```
