---
slug: jvm-mass-assignment
name: Mass Assignment / Over-Binding (JVM)
description: 'Java/Kotlin request binding that writes attacker-controlled fields straight onto a persisted entity — Spring @ModelAttribute on an entity, BeanUtils.populate with the raw parameter map, Jackson readerForUpdating, or a setter loop over request keys. Lets a caller set role, isAdmin, balance, or tenantId. Traces the bound type to see which fields are reachable.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'BeanUtils\.(populate|copyProperties)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: BeanUtils.populate / copyProperties bulk field write
      - regex: '@ModelAttribute\s*(\([^)]*\))?\s*\w+\s+\w+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: '@ModelAttribute binding (verify the bound type is not an entity)'
      - regex: 'readerForUpdating\s*\(|updateValue\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Jackson readerForUpdating / updateValue merges JSON onto an existing object
      - regex: '@RequestBody\s+(?!.*(Dto|DTO|Request|Command|Form|Payload))\w+\s+\w+'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: '@RequestBody bound to a type that is not named as a DTO'
      - regex: 'getParameterMap\s*\(\s*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: raw request parameter map read
where:
  extensions:
    - java
    - kt
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
  preFilter:
    - regex: 'BeanUtils\.(populate|copyProperties)\s*\('
      label: BeanUtils bulk field write
    - regex: '@ModelAttribute'
      label: '@ModelAttribute binding'
    - regex: 'readerForUpdating\s*\(|updateValue\s*\('
      label: Jackson merge onto an existing object
    - regex: '@RequestBody'
      label: '@RequestBody binding (check the bound type)'
    - regex: 'getParameterMap\s*\(\s*\)'
      label: raw parameter map read
    - regex: '@(Entity|Table)\b'
      label: JPA entity (a binding target here is high risk)
  maxFilesPerBatch: 5
references:
  - CWE-915
  - 'OWASP-A04:2021'
---

You are reviewing JVM source code (Java / Kotlin) for mass assignment:
request binding that writes caller-controlled fields onto an object that
is then persisted, letting an attacker set fields the form never showed.

The JVM shape differs from the JavaScript one. There is no object spread
and no prototype pollution. Instead the framework reflectively maps
request keys onto bean setters, so every settable property of the bound
type is reachable unless something restricts it.

**The core question is always: which type is bound, and which of its
fields are settable?** Binding a DTO with three fields is fine. Binding
the JPA entity is not, because `role`, `enabled`, `tenantId`, and
`balance` are all settable through the same mechanism.

## What to look for

**Spring `@ModelAttribute` on an entity:**
```java
@PostMapping("/account")
public String update(@ModelAttribute User user) {   // User is @Entity
    return repo.save(user).getId();                 // role/enabled bindable
}
```

**Apache Commons `BeanUtils.populate` with the raw parameter map:**
```java
User u = repo.findById(id).orElseThrow();
BeanUtils.populate(u, request.getParameterMap());   // every setter reachable
repo.save(u);
```

**Jackson merge onto a loaded entity:**
```java
User u = repo.findById(id).orElseThrow();
mapper.readerForUpdating(u).readValue(requestBody); // unknown fields applied
```

**`@RequestBody` bound straight to the entity:**
```java
@PutMapping("/users/{id}")
public User update(@PathVariable Long id, @RequestBody User incoming) {
    incoming.setId(id);
    return repo.save(incoming);       // client chose every other field
}
```

## True positive criteria

Flag when ALL of the following hold:

1. A request-bound object is written from caller-controlled keys, through
   `@ModelAttribute`, `@RequestBody`, `BeanUtils`, or a Jackson merge.
2. The bound type exposes a field the caller should not set. Read the
   type. Look for `role`, `authorities`, `enabled`, `isAdmin`, `verified`,
   `balance`, `credits`, `tenantId`, `ownerId`, `id`, `createdAt`.
3. Nothing restricts the bindable set. A safe binding uses a dedicated DTO
   with only the editable fields, or `@InitBinder` with `setAllowedFields`,
   or Jackson `@JsonIgnore` / `@JsonProperty(access = READ_ONLY)` on every
   sensitive field.

## What to ignore

- Binding to a purpose-built DTO / command / form type whose fields you
  have read and which carries no privileged field.
- A controller with `@InitBinder` calling `setAllowedFields(...)` or
  `setDisallowedFields(...)` that covers the sensitive fields.
- Entities whose sensitive fields carry `@JsonIgnore` or
  `@JsonProperty(access = Access.READ_ONLY)`, when the binding path is
  Jackson.
- `BeanUtils.copyProperties(source, target)` between two server-controlled
  objects, where neither side comes from the request.
- Test code under `src/test/`.

## Examples

True positives:
```java
// role is a settable column on the entity
@PostMapping("/profile")
public void save(@ModelAttribute UserEntity user) { repo.save(user); }

// every request key reaches a setter
BeanUtils.populate(account, req.getParameterMap());
accountRepo.save(account);
```

False positives to skip:
```java
// DTO with exactly the editable fields
@PostMapping("/profile")
public void save(@RequestBody ProfileUpdateDto dto) {
    User u = repo.findById(dto.id()).orElseThrow();
    u.setDisplayName(dto.displayName());
    repo.save(u);
}

// binder restricts the bindable set
@InitBinder
void init(WebDataBinder binder) { binder.setAllowedFields("displayName", "bio"); }
```

If caller-controlled keys reach the setters of a persisted type, and no
DTO, allowlist, or per-field annotation restricts which fields are
bindable, treat it as a finding.
