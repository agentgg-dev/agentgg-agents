---
slug: py-nosql-injection
name: NoSQL Injection (Python / MongoDB)
description: PyMongo / Motor queries using $where with f-strings, json.loads on request input fed into queries, or $regex from request values — allows operator smuggling or server-side JS execution. Walker mode traces request data through validators.
version: 0.1.0
author: agentgg
mode: walker
tech: [python]
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.py"
excludePatterns:
  - "**/tests/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/migrations/**"
  - "**/__pycache__/**"
preFilter:
  - regex: "[\"']\\$where[\"']\\s*:\\s*f[\"']"
    label: "$where with f-string"
  - regex: "[\"']\\$where[\"']\\s*:\\s*[\"'][^\"']*[\"']\\s*[+%]"
    label: "$where with %/+ formatting"
  - regex: "json\\.loads\\s*\\(\\s*request\\."
    label: "json.loads on request data (potential query smuggling)"
  - regex: "[\"']\\$regex[\"']\\s*:\\s*request\\."
    label: "$regex bound to request input"
  - regex: "re\\.compile\\s*\\(\\s*request\\."
    label: "re.compile on request input"
  - regex: "__raw__\\s*=\\s*\\{[^}]*[\"']\\$where[\"']"
    label: "MongoEngine __raw__ with $where"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-943
  - OWASP-A03:2021
---

You are reviewing Python source code for NoSQL injection in PyMongo,
Motor, or MongoEngine — patterns where request input reaches a MongoDB
query in a way that allows an attacker to inject operators or execute
server-side JavaScript.

**Walker mode advantage:** the request value may be funneled through
a pydantic model, a marshmallow schema, or a `re.escape()` helper.
Follow the variable backwards through imports and function calls —
if a schema validates the type before the query, the operator-
smuggling vector is closed.

## What to look for

**`$where` with f-strings or string formatting:**
```python
coll.find({"$where": f"this.x == '{name}'"})
db.users.find({'$where': "this.id == " + uid})
```
`$where` evaluates JavaScript server-side. Interpolating user input
into its value is equivalent to eval injection.

**`json.loads(request.*)` passed as a query filter:**
```python
q = json.loads(request.json["filter"])
coll.find(q)
```
Allows the caller to supply MongoDB operators: `{"$ne": null}`,
`{"$where": "..."}`, etc.

**`$where` inside an aggregation pipeline:**
```python
coll.aggregate([{"$match": {"$where": f"this.score > {score}"}}])
```

**`$regex` bound to request input:**
```python
coll.find({"name": {"$regex": request.args.get("q")}})
```
A caller-controlled regex is a ReDoS vector and allows crafting
patterns that match unintended documents. Validate the value and
limit regex options before use.

**`re.compile(request.*)` used in a query:**
```python
pattern = re.compile(request.args.get("pattern"))
coll.find({"field": pattern})
```

**MongoEngine `__raw__` with user input:**
```python
Model.objects(__raw__={"$where": f"this.x == '{q}'"})
```

## True positive criteria

Flag when ANY of the following hold:

1. `$where` in a query or pipeline receives a value containing user
   input (f-string, `%` format, `+` concat, `.format()`).
2. `json.loads` on request data is passed directly as a query filter.
3. `$regex` or `re.compile` on request data used in a query.
4. `__raw__` in MongoEngine with user-controlled `$where`.

## What to ignore

- `$where` with a fully hardcoded string.
- `$regex` where the value has been escaped with `re.escape()` before
  use and only string matching (no operator injection) is possible.
- `json.loads` output that is then validated with a schema (pydantic,
  marshmallow) before being used as a query.
- Test / migration files.

## Examples

True positives:
```python
# $where with f-string
coll.find({"$where": f"this.name == '{request.args.get('name')}'"})

# json.loads operator smuggling
q = json.loads(request.get_json()["filter"])
db.collection.find(q)

# $regex from request
coll.find({"username": {"$regex": request.form["search"]}})
```

False positives to skip:
```python
# re.escape applied
pattern = re.escape(request.args.get("q", ""))
coll.find({"name": {"$regex": f"^{pattern}"}})

# Hardcoded $where
coll.find({"$where": "this.status == 'active'"})

# Pydantic validation before query
class Filter(BaseModel):
    name: str
f = Filter(**request.get_json())
coll.find({"name": f.name})
```
