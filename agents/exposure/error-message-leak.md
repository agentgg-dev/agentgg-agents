---
slug: error-message-leak
name: Error Message Leak to Client
description: 'Catch blocks that return err.message, err.stack, err.toString(), or String(err) in HTTP responses — leaks stack traces, DB error text, internal file paths, and infrastructure details.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    files:
      - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
      - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
      - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
      - '**/endpoints/**/*.{ts,tsx,js,jsx,mjs}'
    patterns:
      - regex: \.printStackTrace\s*\(
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: printStackTrace call
      - regex: '@ExceptionHandler\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring exception handler
      - regex: (ResponseEntity|return)[^;]{0,160}\.getMessage\s*\(\s*\)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: exception message returned to the caller
      - regex: getStackTrace\s*\(\s*\)
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: stack trace read
      - regex: include-(stacktrace|message|exception)\s*[:=]
        in:
          - '**/application*.{properties,yml,yaml}'
          - '**/bootstrap*.{properties,yml,yaml}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring Boot error response detail setting
where:
  filePatterns:
    - '**/app/api/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/app/**/route.{ts,tsx,js,jsx,mjs}'
    - '**/pages/api/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/routes/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/endpoints/**/*.{ts,tsx,js,jsx,mjs}'
    - '**/*Controller.{java,kt}'
    - '**/*Advice.{java,kt}'
    - '**/*ExceptionHandler.{java,kt}'
    - '**/application*.{properties,yml,yaml}'
    - '**/bootstrap*.{properties,yml,yaml}'
  preFilter:
    - semgrepRule: exposure/error-message-in-response
      label: Raw error message or stack trace returned in HTTP response
    - regex: \.printStackTrace\s*\(
      label: printStackTrace
    - regex: '@ExceptionHandler\s*\('
      label: Spring exception handler
    - regex: \.getMessage\s*\(\s*\)
      label: exception message (verify it is not returned)
    - regex: getStackTrace\s*\(\s*\)
      label: stack trace read
    - regex: include-(stacktrace|message|exception)\s*[:=]
      label: Spring Boot error response detail setting
  excludePatterns:
    - '**/src/test/**'
    - '**/test/**'
    - '**/target/**'
    - '**/build/**'
references:
  - CWE-209
  - CWE-200
  - 'OWASP-A05:2021'

---

You are reviewing HTTP route handlers for error messages that leak
internal details into the response body. Stack traces, raw database
error text, internal file paths, and infrastructure details are
fingerprints attackers use to map your application.

## What to look for

**Catch block returning `err.message`:**
```ts
try {
  await run();
} catch (err) {
  return Response.json({ error: err.message });
}
```
`err.message` from a database driver looks like:
`"duplicate key value violates unique constraint \"users_email_key\" Detail: Key (email)=(test@example.com) already exists."`
That tells the attacker the column name and current values.

**Catch block returning `err.stack`:**
```ts
} catch (err) {
  return Response.json({ stack: err.stack });
}
```
Stack traces leak file paths, module structure, line numbers.

**Catch block returning `err.toString()` or `String(err)`:**
```ts
} catch (err) {
  return new Response(err.toString(), { status: 500 });
}
```

**500 responses that include arbitrary error context:**
```ts
return NextResponse.json({ message: error.message, trace: error.stack }, { status: 500 });
```

**Spring Boot configuration that adds error detail to every error response:**
```properties
server.error.include-stacktrace=always
server.error.include-message=always
server.error.include-exception=true
```
With these set, the default `/error` response carries the stack trace,
the exception message or the exception class name for every unhandled
exception. No handler code is involved, so a catch-block review does not
see it.

## True positive criteria

Flag when ALL of the following hold:

1. A `catch (err)` block exists in an HTTP route handler.
2. The catch block returns a response whose body includes `err.message`,
   `err.stack`, `err.toString()`, `String(err)`, or the entire error
   object serialized.

Also flag a Spring Boot configuration file that sets
`server.error.include-stacktrace` or `server.error.include-message` to
`always` or `on-param`, or sets `server.error.include-exception` to `true`.
`on-param` counts because any caller can add the parameter. Do not flag
`never`, or a file whose name limits it to a `dev`, `local` or `test`
profile.

## What to ignore

- Returning a static error message: `{ error: "internal server error" }`.
- Returning a sanitized error: a function `toUserError(err)` that
  translates known error classes to user-safe messages.
- Catch blocks that log the error server-side but return a generic
  response: `console.error(err); return Response.json({ error: "failed" }, { status: 500 })`.
- Test / mock servers.

## Examples

True positives:
```ts
try {
  await createUser(req.body);
} catch (err) {
  return Response.json({ error: err.message });
}

try {
  await run();
} catch (error) {
  return NextResponse.json({ trace: error.stack }, { status: 500 });
}

try {
  await query(sql);
} catch (err) {
  return res.send(err.toString());
}
```

False positives to skip:
```ts
try {
  await run();
} catch (err) {
  console.error("operation failed", err);   // log server-side
  return Response.json({ error: "failed" }, { status: 500 });
}

// Sanitized error mapping
try {
  await run();
} catch (err) {
  if (err instanceof ValidationError) {
    return Response.json({ error: err.publicMessage }, { status: 400 });
  }
  return Response.json({ error: "internal error" }, { status: 500 });
}
```
