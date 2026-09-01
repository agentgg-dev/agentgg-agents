---
slug: dom-xss
name: DOM-Based XSS Sources and Sinks
description: 'Untrusted DOM sources (location.href, window.name, document.referrer) flowing into dangerous sinks (innerHTML, document.write, eval, setTimeout with string, jQuery html/append/after, location.assign) without sanitization — enables DOM XSS.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'innerHTML|document\.write|\.html\s*\(|location\.href|window\.name|document\.referrer|document\.URL'
        in:
          - '**/*.{js,ts,jsx,tsx,html,htm}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/build/**'
          - '**/.next/**'
        label: DOM XSS source or sink present in client-side files
where:
  extensions:
    - js
    - ts
    - jsx
    - tsx
    - html
    - htm
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/.next/**'
    - '**/*.test.*'
    - '**/*.spec.*'
  preFilter:
    - regex: '(?:element|el|node|div|span|container|wrapper|html|body)\.innerHTML\s*='
      label: innerHTML assignment
    - regex: 'document\.write\s*\(|document\.writeln\s*\('
      label: document.write/writeln
    - regex: 'eval\s*\(|new\s+Function\s*\('
      label: eval or Function constructor
    - regex: 'set(?:Timeout|Interval|Immediate)\s*\(\s*[''"`]'
      label: setTimeout/setInterval with string argument
    - regex: 'jQuery\s*\(.*\)\.(?:html|append|appendTo|after|before|prepend|replaceWith)\s*\('
      label: jQuery unsafe DOM manipulation
    - regex: '(?:location|window\.location)\.(?:href|replace|assign)\s*='
      label: location.href/assign assignment
    - regex: 'document\.(?:URL|referrer|documentURI|baseURI)|window\.name|location\.(?:hash|search|pathname)'
      label: DOM XSS source read
    - regex: '\.insertAdjacentHTML\s*\('
      label: insertAdjacentHTML
    - regex: 'createContextualFragment\s*\('
      label: createContextualFragment
references:
  - CWE-79
  - 'OWASP-A03:2021'
---

You are reviewing client-side JavaScript for DOM-based XSS: attacker-controlled values read from DOM sources and written to dangerous sinks without sanitization.

## Sources (attacker-controlled)

These values can be controlled by an attacker without server interaction:
- `location.href`, `location.hash`, `location.search`, `location.pathname`
- `window.name` (set by the opener page)
- `document.URL`, `document.referrer`, `document.documentURI`, `document.baseURI`
- `document.cookie` (if attacker has a subdomain or XSS elsewhere)

## Sinks (dangerous write operations)

### HTML sinks — execute arbitrary HTML/script

```js
element.innerHTML = userInput;                         // XSS if no sanitization
element.outerHTML = userInput;
document.write(userInput);
element.insertAdjacentHTML('beforeend', userInput);
document.createRange().createContextualFragment(userInput);
```

### JavaScript execution sinks

```js
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 1000);     // string arg — eval-equivalent
setInterval(userInput, 500);     // string arg — eval-equivalent
```

### jQuery sinks

```js
$(userInput);                    // jQuery(html) — creates DOM from HTML string
$('div').html(userInput);        // sets innerHTML
$('div').append(userInput);      // appends HTML string
$('div').after(userInput);
$('div').before(userInput);
$('div').prepend(userInput);
$('div').replaceWith(userInput);
$.globalEval(userInput);         // explicit eval
```

### Navigation sinks (also XSS via javascript: URIs)

```js
location.href = userInput;       // javascript: URI leads to XSS
location.assign(userInput);
location.replace(userInput);
```

## True positive criteria

Flag at critical when a value read from `location.hash`, `location.search`, `window.name`, or `document.referrer` is passed without sanitization to `innerHTML`, `document.write`, `eval`, or jQuery's `html()`/`append()`.

Flag at high for indirect flows: the source is parsed or decoded before reaching the sink but no sanitization library (DOMPurify, sanitize-html) is applied.

## What to ignore

- Sinks receiving only hardcoded strings with no user-input flow
- `DOMPurify.sanitize(userInput)` applied before the sink — safe if the purify config is not overly permissive
- `textContent` or `innerText` assignments — these do not interpret HTML, safe for text values
- `setTimeout(fn, delay)` where the first argument is a function reference, not a string

## Examples

**Vulnerable:**
```js
const params = new URLSearchParams(location.search);
document.getElementById('msg').innerHTML = params.get('message');
```

```js
const hash = location.hash.slice(1);
eval(decodeURIComponent(hash));
```

**Safe:**
```js
const params = new URLSearchParams(location.search);
document.getElementById('msg').textContent = params.get('message'); // textContent, not innerHTML
```

```js
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

Report: the source read (location.hash, window.name, etc.), the data flow path to the sink, the specific sink used, and whether any sanitization is applied in between.
