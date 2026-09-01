---
slug: nodejs-express-lfr
name: Express Template Render with User Input (LFR)
description: 'Express res.render() called with a template name derived from user input, or Handlebars/Pug template engines rendering user-controlled partials — allows local file read and path traversal outside the views directory.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'res\.render\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\$|`[^`]*\$\{)'
        in:
          - '**/*.{js,ts,mjs,cjs}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/__tests__/**'
          - '**/*.test.{js,ts}'
          - '**/*.spec.{js,ts}'
        label: res.render with user-controlled template name
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/__tests__/**'
    - '**/*.test.{js,ts,mjs}'
    - '**/*.spec.{js,ts,mjs}'
    - '**/.next/**'
  preFilter:
    - regex: 'res\.render\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)'
      label: res.render with request property as template name
    - regex: 'res\.render\s*\(\s*`[^`]*\$\{'
      label: res.render with template literal template name
    - regex: 'res\.render\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[,)]'
      label: res.render with variable template name (trace origin)
    - regex: '\.render\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*,\s*\{'
      label: template engine render with variable name
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-22
  - CWE-98
  - 'OWASP-A01:2021'
---

You are reviewing Express.js (and other Node.js template engine) code for Local File Read via user-controlled template names. When `res.render()` receives a template name from user input, an attacker can traverse outside the views directory and read arbitrary files.

## The vulnerability

Express's `res.render()` resolves template names relative to the configured views directory:
```js
app.set('views', path.join(__dirname, 'views'));
res.render('home');  // renders views/home.hbs
```

If the template name comes from user input:
```js
app.get('/page/:name', (req, res) => {
  res.render(req.params.name);  // VULNERABLE
});
```

An attacker requests `/page/../../../etc/passwd` and the template engine tries to read `/etc/passwd` as a template file. With Handlebars (HBS), this returns the file contents as-is (it's not valid HBS but the content is returned in the error or response body). With EJS, arbitrary file read is straightforward. With Pug, the file is parsed as Pug and errors reveal the content.

## Affected template engines

**Handlebars (HBS):** `res.render('../../../etc/passwd')` reads the file and returns its content in an error message or partial output.

**EJS:** `res.render('../../../etc/passwd')` executes the file as EJS. Any `<%= ... %>` tags in the file execute, and the raw content is returned otherwise.

**Pug:** similar — the file is parsed as Pug, but file contents appear in parse error messages.

## What to look for

```js
// Direct user input as template name
app.get('/view/:template', (req, res) => {
  res.render(req.params.template);  // VULNERABLE
});

// Template literal with user input
app.get('/page', (req, res) => {
  res.render(`pages/${req.query.page}`);  // VULNERABLE — page=../../etc/passwd
});

// Variable that originates from user input
app.post('/render', (req, res) => {
  const view = req.body.view;  // user-controlled
  res.render(view, { data });  // VULNERABLE
});
```

## True positive criteria

Flag when ALL hold:
1. `res.render()` (or equivalent template engine `render()`) receives a template name
2. The name is derived from user-controlled input: `req.params`, `req.query`, `req.body`, or a variable traced back to these
3. No allowlist validation restricts the template name to known-safe values

Safe pattern:
```js
const ALLOWED_TEMPLATES = new Set(['home', 'about', 'contact']);
const template = req.params.name;
if (!ALLOWED_TEMPLATES.has(template)) return res.status(400).send('Invalid page');
res.render(template);  // SAFE — allowlist enforced
```

## What to ignore

- Hardcoded template names: `res.render('index', data)` — no user input
- Template names from a database lookup by ID (the name came from your data, not directly from user input)
- Template names validated against a strict allowlist before use

## Cross-file analysis

When `res.render(variable)` is found, trace where `variable` comes from:
1. Is it directly `req.params.name`, `req.query.page`, `req.body.view`? If yes: finding.
2. Is it from a DB lookup? Trace the query — if the DB value was originally stored from user input without sanitization, it's still a finding.
3. Is there a validation function between the source and the render call? Read it.

## Examples

True positives:
```js
// Express + HBS — direct path traversal
router.get('/help/:section', (req, res) => {
  res.render(`help/${req.params.section}`);
  // GET /help/../../../../etc/passwd → reads /etc/passwd
});
```
```js
// Template name from query param
app.get('/page', (req, res) => {
  const view = req.query.view || 'home';
  res.render(view);  // no allowlist check
});
```

False positives to skip:
```js
// Allowlist validation
const VALID_VIEWS = ['home', 'about', 'docs'];
if (!VALID_VIEWS.includes(req.params.page)) return res.sendStatus(404);
res.render(req.params.page);
```
```js
// Hardcoded name
res.render('dashboard', { user: req.user });
```

Report the template engine in use, how the template name is sourced from the request, and whether any path confinement or allowlist check exists.
