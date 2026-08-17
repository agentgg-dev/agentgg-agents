---
slug: js-vue-unsafe-html
name: Vue.js Unsafe HTML Injection
description: 'v-html directive and render-function innerHTML binding with untrusted input in Vue.js and Nuxt. Bypasses Vue template auto-escaping and is equivalent to setting innerHTML directly.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    extensions:
      - vue
    patterns:
      - regex: 'v-html\s*='
        in:
          - '**/*.{vue,js,ts,jsx,tsx}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.nuxt/**'
        label: v-html directive
  prompt: 'Run only if this project uses Vue.js — look for .vue files or vue in package.json.'
where:
  extensions:
    - vue
    - js
    - ts
    - jsx
    - tsx
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.nuxt/**'
  preFilter:
    - regex: 'v-html\s*='
      label: v-html directive
    - regex: 'h\s*\([^)]*innerHTML'
      label: render function h() with innerHTML
    - regex: '\$refs\.[a-zA-Z_][a-zA-Z0-9_.]*\.innerHTML\s*='
      label: $refs innerHTML assignment
    - regex: 'Vue\.compile\s*\('
      label: Vue.compile with dynamic template
    - regex: 'useHead\s*\([^)]*innerHTML'
      label: Nuxt useHead innerHTML
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-79
  - 'OWASP-A03:2021'
---

You are reviewing Vue.js and Nuxt source code for HTML injection via
sinks that bypass Vue's automatic template escaping.

**Cross-file analysis:** trace the value bound to `v-html` back to
its source. It is commonly a computed property or a Pinia/Vuex store
value that originates from a fetch call, route param, or database
field. Open the store or composable and verify whether sanitization
is applied before the value is stored.

## What to look for

**`v-html` directive**
```html
<div v-html="userContent"></div>
<p v-html="post.body"></p>
<component v-html="message" />
```
Vue auto-escapes all normal template bindings (`{{ value }}`), but
`v-html` sets `innerHTML` directly. Any untrusted value bound here
is a stored or reflected XSS. The directive name is the entire
warning: it exists only for cases where the HTML is known-safe
(e.g. sanitized CMS content).

**Render function with `innerHTML`**
```js
// Options API
render() {
  return h('div', { innerHTML: this.userContent });
}

// Composition API
const vnode = h('div', { innerHTML: props.body });
```
`h()` accepts a `innerHTML` prop that behaves identically to the
`v-html` directive. Often harder to spot because it appears in JS
rather than a template.

**`$refs` innerHTML assignment in lifecycle hooks**
```js
mounted() {
  this.$refs.container.innerHTML = this.userHtml;
}

// Composition API
onMounted(() => {
  myRef.value.innerHTML = props.content;
});
```
Bypasses Vue's reactivity system entirely and writes raw HTML to the
DOM. Commonly found in rich-text rendering components.

**`Vue.compile()` with dynamic templates**
```js
const template = userInput; // from API or DB
const Component = Vue.defineComponent({ template });
// or
const render = Vue.compile(template);
```
Compiles an arbitrary string as a Vue template. If `template` comes
from user input this is template injection, not just XSS: the attacker
can call any JavaScript accessible from the template scope.

**Nuxt `useHead` / `useServerHead` with `innerHTML`**
```js
useHead({
  script: [{ innerHTML: userControlledScript }],
  style:  [{ innerHTML: userControlledCss }],
});
```
`innerHTML` inside `useHead` script/style entries is injected into
the document during SSR without escaping. It is not sanitized by Vue
or Nuxt automatically.

## True positive criteria

Flag when ALL of the following hold:

1. A sink is present: `v-html` directive, `h()` with `innerHTML`,
   `$refs.el.innerHTML =`, `Vue.compile()`, or `useHead` with
   `innerHTML`.
2. The value has an untrusted origin: route params, query strings,
   request body, database content that users can write, third-party
   API responses, or Pinia/Vuex state populated from any of those.
3. No adequate HTML sanitization is applied on the path between the
   source and the sink. Adequate means DOMPurify, sanitize-html, or
   an equivalent library that strips script-execution vectors —
   not just escaping special characters, which does not protect a raw
   HTML context.

## What to ignore

- `v-html` bound to a hardcoded string literal with no interpolation.
- Content that passed through a verified sanitizer (DOMPurify,
  sanitize-html) before reaching the sink. Check that the sanitized
  output — not the raw input — is what is bound.
- Markdown rendered via `marked()` or `unified()` where the source
  is from a static file in the repo, not user input.
- `v-html` in Storybook stories or test fixtures rendering controlled
  synthetic markup never served to real users.
- `Vue.compile()` where the template string is a hardcoded constant
  in the source file.
- `useHead` `innerHTML` containing only static strings with no
  interpolation.

## Examples

True positives:
```html
<!-- route param bound directly -->
<div v-html="$route.query.preview"></div>

<!-- Pinia store value from API response -->
<article v-html="postStore.body"></article>
```
```js
// render function, prop from parent who got it from fetch
render() {
  return h('div', { innerHTML: this.apiResponse.html });
}

// $refs write in mounted, value from DB
mounted() {
  this.$refs.editor.innerHTML = this.post.content;
}

// Vue.compile with user-supplied template string
const tpl = await fetchTemplateFromUser();
app.component('Dynamic', { render: Vue.compile(tpl) });

// Nuxt useHead — script body from CMS API
useHead({ script: [{ innerHTML: cmsData.trackingScript }] });
```

False positives to skip:
```html
<!-- hardcoded, no user input -->
<div v-html="'<strong>Bold</strong>'"></div>

<!-- DOMPurify applied before binding -->
<div v-html="DOMPurify.sanitize(post.body)"></div>
```
```js
// static template, no user data
Vue.compile('<div class="wrapper"><slot /></div>');
```
