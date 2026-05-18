---
slug: unsafe-deserialization
name: Unsafe Deserialization
description: JSON.parse / yaml.load / pickle.loads / Java ObjectInputStream on user input without schema validation — allows prototype pollution, code execution (Python/Java), or untyped objects reaching trusted paths. Walker mode follows downstream usage to confirm severity.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs,py,java,kt,rb}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs,py}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/tests/**"
  - "**/spec/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "JSON\\.parse\\s*\\(\\s*(req|request|ctx)\\.(body|text|json)"
    label: "JSON.parse on request body"
  - regex: "JSON\\.parse\\s*\\(\\s*(await\\s+)?(req|request)\\.(text|json)\\s*\\(\\s*\\)\\s*\\)"
    label: "JSON.parse on awaited req.text()/req.json()"
  - regex: "yaml\\.(load|unsafeLoad)\\s*\\(|yaml\\.unsafe_load\\s*\\("
    label: "Unsafe yaml.load"
  - regex: "pickle\\.loads?\\s*\\("
    label: "Python pickle.loads"
  - regex: "ObjectInputStream\\s*\\(|\\.readObject\\s*\\("
    label: "Java ObjectInputStream"
  - regex: "Marshal\\.load\\s*\\("
    label: "Ruby Marshal.load"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-502
  - OWASP-A08:2021
---

You are reviewing source code for deserialization of untrusted input
without schema validation.

**Walker mode advantage:** the parsed result may be passed through a
Zod/Joi/pydantic schema in the next function call, which closes the
bug. Trace the value: was `data` validated before being used as
`db.user.update({ data })`? Also follow `yaml.load(...)` to confirm
the loader argument — `js-yaml >= 4` is safe by default; older
versions are not. The severity depends on the format:

- **JSON.parse:** "safe" parser, but the resulting object has no
  type guarantees — downstream code may dereference fields that
  don't exist (`req.body.role`) or fail to validate types, leading
  to logic bugs.
- **YAML `load` / `safe_load` misuse:** YAML can construct
  arbitrary Python objects in unsafe mode — full RCE.
- **Python `pickle.loads`:** RCE on untrusted input.
- **Java `ObjectInputStream.readObject`:** RCE via gadget chains.
- **Ruby `Marshal.load`:** RCE.

## What to look for

**JavaScript / TypeScript:**
```ts
const data = JSON.parse(req.body);
const x = JSON.parse(request.body);
const cfg = JSON.parse(body.config);
const payload = JSON.parse(await req.text());
eval(JSON.parse(input));
const fn = new Function(JSON.parse(spec));
const config = yaml.load(rawYaml);   // js-yaml unsafe mode
```

**Python:**
```python
import pickle
data = pickle.loads(request.data)        # RCE

import yaml
cfg = yaml.load(stream)                  # RCE (uses default Loader)
cfg = yaml.unsafe_load(stream)           # RCE

# Safe forms:
cfg = yaml.safe_load(stream)
cfg = yaml.load(stream, Loader=yaml.SafeLoader)
```

**Java:**
```java
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();
```

**Ruby:**
```ruby
data = Marshal.load(params[:data])
```

## True positive criteria

Flag when ANY of the following hold:

1. `JSON.parse(req.body|request.body|body.*|params.*|query.*)` is
   called and the result is used without being passed through a
   schema parser (Zod, Joi, Yup, io-ts) that rejects unknown shapes.
2. `eval(JSON.parse(...))` or `new Function(JSON.parse(...))` —
   double sin: deserialize then execute.
3. `yaml.load(input)` in JS (js-yaml) or `yaml.load(stream)` /
   `yaml.unsafe_load` in Python — both deserialize arbitrary types.
4. `pickle.loads(...)` on untrusted input.
5. `ObjectInputStream.readObject` on untrusted input (Java).
6. `Marshal.load` on untrusted input (Ruby).

## What to ignore

- `JSON.parse(...)` followed by schema validation:
  `const data = schema.parse(JSON.parse(...))`.
- `yaml.safe_load(stream)` (Python) — safe loader.
- `yaml.load(stream, Schema)` (js-yaml) with `JSON_SCHEMA` or
  `FAILSAFE_SCHEMA`.
- Internal trusted serialization (between services you control,
  signed with HMAC).
- Test files.

## Examples

True positives:
```ts
// JSON.parse without validation
const data = JSON.parse(await req.text());
await db.user.update({ where: { id }, data });   // any fields accepted

// yaml.load with default schema (unsafe in js-yaml < 4)
const cfg = yaml.load(req.body);

// eval of parsed JSON
const code = JSON.parse(req.body.script);
eval(code);
```

```python
# pickle on request data
import pickle
data = pickle.loads(request.get_data())   # RCE

# yaml.load default
config = yaml.load(open("user.yaml"))     # if file is user-controlled
```

False positives to skip:
```ts
// Zod after JSON.parse
const parsed = userSchema.parse(JSON.parse(await req.text()));

// yaml safe schema
const cfg = yaml.load(stream, { schema: yaml.JSON_SCHEMA });
```

```python
yaml.safe_load(stream)
```
