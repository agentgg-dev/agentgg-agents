---
slug: nodejs-mustache-xss
name: Mustache/Handlebars Escape Disabled (XSS)
description: 'Template rendering with HTML escaping explicitly disabled (escapeMarkup=false, triple-stache {{{}}}, Handlebars SafeString, or noEscape:true) while rendering user-controlled content — allows stored or reflected XSS.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\.escapeMarkup\s*=\s*false|noEscape\s*:\s*true|new\s+Handlebars|require\s*\(\s*[''"]mustache[''"]\s*\)|require\s*\(\s*[''"]handlebars[''"]\s*\)'
        in:
          - '**/*.{js,ts,mjs,cjs,jsx,tsx}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Mustache/Handlebars import or escape-disabled config
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
    - jsx
    - tsx
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/*.test.{js,ts,mjs}'
    - '**/*.spec.{js,ts,mjs}'
    - '**/__tests__/**'
  preFilter:
    - regex: '\.escapeMarkup\s*=\s*false'
      label: Mustache escapeMarkup disabled globally
    - regex: 'noEscape\s*:\s*true'
      label: Handlebars noEscape option enabled
    - regex: '\{\{\{[^}]+\}\}\}'
      label: Handlebars triple-stache (unescaped output)
    - regex: 'new\s+Handlebars\.SafeString\s*\('
      label: Handlebars SafeString wrapping user content
    - regex: '\.compile\s*\([^)]+,\s*\{[^}]*noEscape'
      label: Handlebars compile with noEscape
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-79
  - 'OWASP-A03:2021'
---

You are reviewing Node.js source code for XSS vulnerabilities caused by disabling HTML escaping in Mustache or Handlebars template rendering. By default these engines escape `<`, `>`, `&`, `"`, and `'` — disabling that opens the output to raw HTML injection.

## Escape-bypass mechanisms

**Mustache — global escape disable:**
```js
const Mustache = require('mustache');
Mustache.escapeMarkup = false;  // ALL output is now unescaped
const html = Mustache.render(template, { name: userInput });  // XSS if name contains <script>
```

**Handlebars — per-compile noEscape:**
```js
const template = Handlebars.compile(templateStr, { noEscape: true });
const html = template({ title: req.query.title });  // unescaped
```

**Handlebars — triple-stache in template:**
```handlebars
<div>{{{userContent}}}</div>
```
The triple `{{{ }}}` intentionally bypasses escaping. It is safe only if the value is trusted HTML (e.g., a CMS rich-text field that was already sanitized).

**Handlebars — SafeString:**
```js
Handlebars.registerHelper('raw', function(value) {
  return new Handlebars.SafeString(value);  // bypasses escaping
});
```
SafeString tells Handlebars the value is pre-sanitized HTML. If user input reaches it without sanitization, it's XSS.

## True positive criteria

Flag when ALL hold:
1. Escaping is disabled (via `escapeMarkup=false`, `noEscape:true`, `{{{ }}}`, or `SafeString`)
2. A user-controlled value reaches the template context key that is rendered unescaped
3. The output goes to an HTML response (not an email, PDF, or plain text context)

## What to ignore

- `{{{ }}}` or `SafeString` used only with values from a server-side CMS or rich-text field that has already been sanitized by a library like DOMPurify or sanitize-html before storage
- Templates rendering entirely hardcoded content with no user input in the unescaped slots
- Plain-text email rendering where the output is not parsed as HTML
- Test templates in `__tests__/` or `*.spec.*` files

## Cross-file analysis

When `escapeMarkup = false` is found globally, check every `Mustache.render()` call in the codebase — all of them are now unescaped. Trace the data objects passed in to see which keys include user input.

For `SafeString` helpers, find every call site of that helper in templates and trace whether user content reaches it.

## Examples

True positives:
```js
// Global escape disabled — every render is now raw HTML
Mustache.escapeMarkup = false;
app.get('/profile', (req, res) => {
  const html = Mustache.render(profileTemplate, {
    bio: req.body.bio  // user-supplied, rendered unescaped
  });
  res.send(html);
});
```
```handlebars
{{!-- template.hbs --}}
<div class="comment">{{{comment.body}}}</div>
{{!-- comment.body is user-submitted text --}}
```

False positives to skip:
```js
// Triple-stache but value is sanitized before storage
const sanitized = sanitizeHtml(userInput, { allowedTags: [] });
// sanitized stored in DB, rendered with {{{ }}}
```
```js
// noEscape on a template that only renders internal config
const template = Handlebars.compile(internalTemplate, { noEscape: true });
const html = template({ version: packageJson.version });  // no user input
```

Report the escape-bypass mechanism used, the template key(s) that receive user input, and the response context (HTML page, email, etc.).
