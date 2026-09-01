---
slug: python-unsafe-deserialization
name: Python Unsafe Deserialization
description: 'Use of pickle, marshal, or PyYAML yaml.load() on untrusted data, enabling arbitrary code execution during deserialization. pickle.loads() on user-supplied bytes can execute any Python code.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'import\s+pickle\b|import\s+cPickle\b|from\s+pickle\s+import|from\s+cPickle\s+import|import\s+marshal\b|import\s+yaml\b|from\s+yaml\s+import'
        in:
          - '**/*.py'
        notIn:
          - '**/node_modules/**'
          - '**/vendor/**'
        label: pickle, marshal, or yaml module imported in Python files
where:
  extensions:
    - py
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
  preFilter:
    - regex: 'pickle\.loads?\('
      label: pickle.loads/pickle.load call
    - regex: 'c?Pickle\.loads?\('
      label: cPickle.loads/cPickle.load call
    - regex: 'marshal\.loads?\('
      label: marshal.loads/marshal.load call
    - regex: 'yaml\.load\s*\('
      label: yaml.load call (potentially unsafe without Loader)
    - regex: 'pickle\.Unpickler\('
      label: pickle.Unpickler instantiation
references:
  - CWE-502
  - 'OWASP-A08:2021'
---

You are reviewing Python code for unsafe deserialization. These libraries can execute arbitrary code when deserializing attacker-controlled data.

## Risk by library

### pickle / cPickle (critical)

`pickle.loads()` executes the `__reduce__` method of any class during deserialization. Attacker-crafted pickle bytes can execute arbitrary Python — no workaround exists other than not using pickle on untrusted data.

```python
# critical: deserializes user-supplied bytes
data = pickle.loads(request.data)
obj = pickle.loads(base64.b64decode(request.cookies['session']))
```

### marshal (critical)

Similar to pickle — marshal.loads() on untrusted data can cause arbitrary code execution. Intended for Python bytecode, not user data.

```python
result = marshal.loads(user_provided_bytes)
```

### yaml.load() without Loader (high)

`yaml.load(data)` without a Loader argument defaults to the full YAML loader which can construct arbitrary Python objects:
```python
yaml.load(user_input)                    # dangerous — full Python object construction
yaml.load(user_input, Loader=yaml.FullLoader)  # still dangerous with untrusted data
yaml.safe_load(user_input)              # safe — restricted to basic types
```

## True positive criteria

Flag at critical:
1. `pickle.loads()` / `pickle.load()` / `cPickle.loads()` called with data from HTTP requests, file uploads, user sessions, or any external source
2. `marshal.loads()` on user-supplied bytes
3. `pickle.Unpickler(user_file).load()` where the file comes from user input

Flag at high:
4. `yaml.load(data)` without `Loader=yaml.SafeLoader` where `data` comes from user input or external config files

## What to ignore

- `pickle.loads()` on data generated entirely within the same trusted process (e.g., loading from your own application's cache with no user influence over the bytes)
- `yaml.safe_load()` — this is the safe variant
- `yaml.load(data, Loader=yaml.SafeLoader)` — safe loader explicitly specified

Report: the function called, where the data originates (request body, cookie, file upload, etc.), and whether there is any signature or integrity check applied before deserialization.
