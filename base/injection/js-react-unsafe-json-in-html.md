---
slug: js-react-unsafe-json-in-html
name: Unsafe JSON in HTML Script Tags (React/Next.js)
description: JSON.stringify output embedded in a script tag or dangerouslySetInnerHTML without escaping </script> — allows closing the script tag early to inject HTML. Walker mode traces any safe-stringify helper imports.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/*.{tsx,jsx,ts,js}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*[^}]*JSON\\.stringify"
    label: "dangerouslySetInnerHTML embedding JSON.stringify"
  - regex: "<script[^>]*>[^<]*\\$\\{\\s*JSON\\.stringify"
    label: "<script> tag template-interpolating JSON.stringify"
  - regex: "res\\.send\\s*\\(\\s*`[^`]*<script[^`]*\\$\\{\\s*JSON\\.stringify"
    label: "res.send template embedding JSON.stringify in <script>"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-79
  - OWASP-A03:2021
---

You are reviewing React and Next.js code for a specific XSS variant:
`JSON.stringify` output embedded directly in a `<script>` block or
`dangerouslySetInnerHTML` without escaping `</script>` sequences.

**Walker mode advantage:** projects commonly have a `safeJsonStringify`
or `serializeForScript` helper imported from a shared module. If the
candidate is `safeJsonStringify(state)`, open the helper and verify
it replaces `<`/`>`/`&` (or equivalent escaping). If it's bare
`JSON.stringify`, it's a finding.

## The vulnerability

`JSON.stringify` does not escape `<`, `>`, or `/`. If user-controlled
data ends up in the JSON, an attacker can inject the string
`</script>` inside a string value, which the browser's HTML parser
treats as the end of the script block — regardless of being inside a
JSON string. Everything after it is rendered as HTML, enabling
arbitrary script execution.

```jsx
// VULNERABLE — attacker controls state.user.bio
<script
  dangerouslySetInnerHTML={{
    __html: `window.__INITIAL_STATE__ = ${JSON.stringify(state)}`,
  }}
/>
// If state.user.bio === '</script><script>alert(1)</script>
// the browser closes the script tag and executes the injected script.
```

This pattern is extremely common in SSR frameworks (Next.js Pages
Router, Remix, custom Express SSR) that hydrate client-side state by
injecting it into a `<script>` tag.

## What to look for

1. `JSON.stringify(value)` where the result is:
   - Placed inside a `` `<script>...</script>` `` template literal
   - Passed to `dangerouslySetInnerHTML={{ __html: ... }}`
   - Concatenated into a string that becomes script tag content
   - Written into a `<script>` tag via `document.write` or `innerHTML`

2. Next.js specific patterns:
   - `__NEXT_DATA__` populated via `JSON.stringify` without escaping
   - `getServerSideProps` / `getStaticProps` return values serialized
     into a script tag
   - `<script id="__NEXT_DATA__" type="application/json">` with
     unescaped content

3. The variable being serialized originates (directly or transitively)
   from user input: request params, database rows, API responses, or
   session data that a user can influence.

## Safe alternatives

The fix is to escape `</script>` (and related sequences) in the
JSON output before embedding it in HTML:

```js
// Safe: replace </script> sequences so the HTML parser cannot split the block
function safeJsonStringify(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");
}
```

Next.js itself uses this approach internally. Flag code that uses
plain `JSON.stringify` in an HTML context without this escaping step.

## True positive criteria

Flag when ALL of the following hold:

1. `JSON.stringify` is called and the result reaches an HTML script
   context (script tag body, `dangerouslySetInnerHTML`, or an HTML
   string returned as `text/html`).
2. The serialized value contains or could contain user-controlled data
   (request params, session fields, database content).
3. No escaping of `</script>` / `<` is applied between
   `JSON.stringify` and the HTML context.

## What to ignore

- `JSON.stringify` whose result is only used in an HTTP response body
  with `Content-Type: application/json` (not HTML).
- `JSON.stringify` of a fully hardcoded object with no user input.
- Cases where the output passes through `safeJsonStringify` or an
  equivalent that replaces `<` with `<`.
- Next.js's own internal serialization — it already applies the
  escaping; flag only application-level code that bypasses it.
- Test files that render synthetic controlled data.

## Examples

True positives:
```jsx
// Next.js page — state contains user profile from DB
<script
  dangerouslySetInnerHTML={{
    __html: `window.__STATE__ = ${JSON.stringify(pageProps)}`,
  }}
/>

// Express SSR — req.body fed into hydration payload
res.send(`<script>window.data = ${JSON.stringify(req.body)}</script>`);

// Remix — loader data serialized into script
const script = `<script>window.__loaderData__ = ${JSON.stringify(loaderData)}</script>`;
```

False positives to skip:
```jsx
// application/json response — browser does not parse as HTML
res.json(JSON.stringify(data));

// safeJsonStringify already used
<script dangerouslySetInnerHTML={{ __html: safeJsonStringify(state) }} />

// Fully hardcoded object
<script dangerouslySetInnerHTML={{ __html: JSON.stringify({ version: "1.0" }) }} />
```
