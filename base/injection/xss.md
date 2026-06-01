---
slug: xss
name: Cross-Site Scripting (XSS)
description: 'Untrusted input rendered as raw HTML — dangerouslySetInnerHTML, innerHTML, v-html, template literals in HTML, document.write, and unescaped server-side templates. Follows sanitizer wrappers and helpers.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'dangerouslySetInnerHTML\s*=\s*\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: React dangerouslySetInnerHTML
      - regex: '\.(innerHTML|outerHTML)\s*=\s*[^"''`][^;]*$'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: .innerHTML/outerHTML assigned a non-literal
      - regex: document\.write\s*\(
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: document.write call
      - regex: v-html\s*=
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Vue v-html binding
      - regex: '\[innerHTML\]\s*=|bypassSecurityTrustHtml\s*\('
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: 'Angular [innerHTML] / bypassSecurityTrustHtml'
      - regex: '<%-\s|\{\{\{|!=\s+|\|\s*safe\b'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
          - '**/*.{html,ejs,hbs,njk,pug}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/stories/**'
          - '**/*.stories.{ts,tsx,js,jsx}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Unescaped server template directive (EJS/Handlebars/Pug/Nunjucks)
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - html
    - ejs
    - hbs
    - njk
    - pug
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/stories/**'
    - '**/*.stories.{ts,tsx,js,jsx}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'dangerouslySetInnerHTML\s*=\s*\{'
      label: React dangerouslySetInnerHTML
    - regex: '\.(innerHTML|outerHTML)\s*=\s*[^"''`][^;]*$'
      label: .innerHTML/outerHTML assigned a non-literal
    - regex: document\.write\s*\(
      label: document.write call
    - regex: v-html\s*=
      label: Vue v-html binding
    - regex: '\[innerHTML\]\s*=|bypassSecurityTrustHtml\s*\('
      label: 'Angular [innerHTML] / bypassSecurityTrustHtml'
    - regex: '<%-\s|\{\{\{|!=\s+|\|\s*safe\b'
      label: Unescaped server template directive (EJS/Handlebars/Pug/Nunjucks)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-79
  - 'OWASP-A03:2021'
---

You are reviewing source code for cross-site scripting (XSS) — places
where untrusted input is rendered as raw HTML without encoding,
allowing an attacker to inject arbitrary scripts into a page.

**Cross-file analysis:** the value reaching a sink is often the
output of a `marked()`, `markdown()`, or sanitizer call defined in a
shared module. Open the import and verify: a DOMPurify-wrapped value
is safe; a raw markdown-to-HTML result is not. Also trace the
variable to confirm whether it came from a hardcoded source (safe) or
crossed a trust boundary.

## What to look for

**React**
- `dangerouslySetInnerHTML={{ __html: value }}` where `value` comes
  from props, state, query params, API responses, or the database.
  The prop name is the whole warning — it is only safe when the HTML
  is from a trusted, controlled source (e.g., your own CMS with
  server-side sanitization already applied).

**DOM APIs**
- `element.innerHTML = value` or `element.outerHTML = value` where
  `value` is not a hardcoded string.
- `document.write(value)` with any non-constant argument.
- `element.insertAdjacentHTML("beforeend", value)` — same risk as
  `innerHTML`.
- `element.setHTML(value)` without a Sanitizer config that strips
  script-injection vectors.

**Template literals assembled into HTML**
- A template literal that interpolates a variable AND contains HTML
  tags: `` `<p>${userInput}</p>` ``, `` `<a href="${url}">` ``.
  The HTML string is then passed to innerHTML, returned from an API
  as `text/html`, or injected into the DOM.

**Vue**
- `v-html="value"` binds raw HTML. Equivalent to innerHTML.

**Angular**
- `[innerHTML]="value"` binding bypasses Angular's default escaping.
  Angular does have a built-in sanitizer, but it is bypassable via
  `bypassSecurityTrustHtml()`.
- `DomSanitizer.bypassSecurityTrustHtml(value)` with untrusted input.

**Server-side templates**
- EJS: `<%- value %>` (unescaped output). `<%= value %>` is safe.
- Handlebars / Mustache: `{{{ value }}}` (triple-stache, unescaped).
  `{{ value }}` is safe.
- Nunjucks: `{{ value | safe }}` filter disables autoescaping.
- Pug: `!= value` (unescaped). `= value` is safe.

## True positive criteria

Flag when ALL of the following hold:

1. A sink is present: `dangerouslySetInnerHTML`, `innerHTML`,
   `outerHTML`, `insertAdjacentHTML`, `document.write`, `v-html`,
   `[innerHTML]`, `bypassSecurityTrustHtml`, or an unescaped
   server-side template directive.
2. The value reaching the sink has an untrusted origin: HTTP request
   params/body/headers, database content that originates from user
   input, third-party API responses, file uploads, WebSocket messages,
   or environment variables set by external systems.
3. No adequate sanitization is applied on the same code path. Adequate
   means a dedicated HTML sanitizer library (DOMPurify, sanitize-html,
   Bleach) is called and the sanitized output — not the raw input — is
   what reaches the sink.

## What to ignore

- `dangerouslySetInnerHTML` or `innerHTML` where the value is a
  hardcoded string literal with no interpolation.
- Content from a CMS/database field that is demonstrably sanitized
  server-side before storage AND is not re-rendered with any
  additional interpolation.
- EJS `<%= %>` / Handlebars `{{ }}` / Pug `= ` — these escape by
  default.
- React's normal JSX expressions `{value}` — React text-encodes them.
  Only `dangerouslySetInnerHTML` bypasses this.
- Angular's default template binding `{{ value }}` — Angular
  HTML-encodes it. Only `[innerHTML]` and `bypassSecurityTrust*`
  bypass it.
- Test files, Storybook stories, or fixtures that render synthetic
  controlled markup and are never served to real users.
- Server-side rendered HTML that is returned with `Content-Type:
  text/plain` or `application/json` — XSS requires `text/html`
  delivery to a browser.

## Examples

True positives:
- `<div dangerouslySetInnerHTML={{ __html: comment.body }} />` where
  `comment.body` comes from a database row supplied by users.
- `el.innerHTML = req.query.search` in a client-side search handler.
- `document.write('<script src="' + location.search + '"></script>')`.
- `` return `<p>${req.body.message}</p>`; `` passed to a response with
  `Content-Type: text/html`.
- `<div v-html="post.content" />` where `post.content` is user data.
- `<%- user.bio %>` in an EJS template where `user.bio` is from the
  database.
- `{{{ article.body }}}` in a Handlebars template.

False positives to skip:
- `<div dangerouslySetInnerHTML={{ __html: marked(mdSource) }} />`
  where `mdSource` is a hardcoded markdown string from a `*.md` file
  in the repo (not user input).
- `el.innerHTML = '<span class="highlight">match</span>'` — constant
  string, no interpolation.
- `{user.name}` in JSX — React-encoded, not raw HTML.
- `<%= escape(userInput) %>` — EJS escaped output.
- `DOMPurify.sanitize(html)` result passed to innerHTML — sanitized.

If a sink exists and the value has any plausible path from user input,
flag it. The cost of a missed XSS is script execution in a victim's
browser; the burden is on the code to prove sanitization, not on the
reviewer to rule out every injection scenario.
