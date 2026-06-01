---
slug: ssti
name: Server-Side Template Injection (SSTi)
description: 'Template engines (Pug, Handlebars, Jinja2, ERB, Thymeleaf, Freemarker, EJS) compiling or rendering templates whose source string came from user input — leads to template-language code execution.'
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
    - php
    - java
    - kt
    - cs
references:
  - CWE-1336
  - CWE-94
  - 'OWASP-A03:2021'
---

You are reviewing source code for Server-Side Template Injection
(SSTi) — calls that compile or render a template whose **source
string** is derived from request input, rather than rendering a fixed
template file with user values bound as data.

The danger isn't passing user data into a template (`render('view',
{ name })` is fine). The danger is passing user data **as the template
itself**, because template languages typically expose enough power to
execute arbitrary code in the server runtime.

## What to look for

**Node.js — Pug / Jade:**
```ts
pug.compile(userString)();
pug.render(req.body.template, data);
```

**Node.js — Handlebars:**
```ts
const tpl = Handlebars.compile(req.body.layout);
tpl(data);
```

**Node.js — EJS / Mustache / Nunjucks / Eta:**
```ts
ejs.render(req.body.template, data);
mustache.render(req.query.tpl, data);
nunjucks.renderString(userSource, ctx);
eta.renderString(userSource, ctx);
```

**Python — Jinja2:**
```python
from jinja2 import Template, Environment
Template(request.form["src"]).render(...)
Environment().from_string(user_template).render(...)
```

**Python — Mako:**
```python
mako.template.Template(request.json["t"]).render(...)
```

**Ruby — ERB / Liquid / Slim:**
```ruby
ERB.new(params[:tpl]).result(binding)
Liquid::Template.parse(params[:t]).render(...)
```

**Java — Velocity / Freemarker / Thymeleaf:**
```java
velocityEngine.evaluate(ctx, writer, "ssti", userSource);
new Template("name", new StringReader(userSource), cfg);
templateEngine.process(userSource, ctx);   // Thymeleaf with raw source
```

**Go — text/template / html/template:**
```go
t, _ := template.New("x").Parse(userSource)
t.Execute(w, data)
```

**PHP — Twig / Smarty:**
```php
$loader = new ArrayLoader(['t' => $_POST['tpl']]);
$twig = new Environment($loader);
echo $twig->render('t');
```

**Key smell:** `Engine.parse(...)`, `compile(...)`, `from_string(...)`,
`renderString(...)`, `Template(...)`, `evaluate(...)`, or `new Template(...)`
called with a value that traces back to a request body, query string,
URL parameter, header, or stored user-controlled content.

## True positive criteria

Flag when ALL of the following hold:

1. A template-engine API that accepts a **template source** (string of
   template language) is called.
2. The source argument is, transitively, request input or stored
   user-controlled content (e.g., a record the user wrote earlier).
3. The result is rendered (executed) — not just parsed for inspection.

## What to ignore

- Rendering a fixed template *file* with user data as the data
  context: `res.render("user-profile", { user })` — that's the safe
  pattern. The vulnerability is the **source**, not the data.
- Engines used in a sandboxed mode whose limits are documented and
  enforced (Handlebars `noEscape: false` with `runtime` only — rare
  to see correctly).
- Test fixtures that compile constant strings.
- CLI / build-time tooling that compiles developer-authored templates
  (Storybook, docs generators).

## Examples

True positives:
```ts
// Pug — user-supplied template source
app.post("/render", (req, res) => {
  const tpl = pug.compile(req.body.template);
  res.send(tpl({ name: "x" }));
});

// Handlebars from a stored CMS field
const layoutSrc = await db.layouts.findById(id);   // user-authored
const layout = Handlebars.compile(layoutSrc.body);
res.send(layout(data));
```
```python
# Jinja2 — request value rendered as template
@app.route("/preview", methods=["POST"])
def preview():
    return Template(request.form["src"]).render()
```

False positives to skip:
```ts
// Fixed template file, user data as values — safe
res.render("invoice", { customer, total });
pug.renderFile("views/page.pug", { user: req.user });
```
```python
# Loads template from filesystem by name, not from request
env = Environment(loader=FileSystemLoader("templates"))
env.get_template(name_from_allowlist).render(data)
```

User-rendered Markdown is different — flag that under XSS / dangerous-html
if it ends up in the DOM. SSTi specifically is about *server-side*
code execution via the template language.
