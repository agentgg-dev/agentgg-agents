---
slug: azure-function-handler
name: Azure Function Handler Security
description: Azure Functions — HTTP trigger authLevel anonymous on sensitive operations, missing input validation, managed identity misuse, secrets in app settings. Walker mode correlates function.json bindings with handler code.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: normal
outputType: finding
filePatterns:
  - "**/functions/**/*.{ts,tsx,js,jsx,mjs,cjs,py,cs,java}"
  - "**/*Function*.{ts,cs,py,java}"
  - "**/function.json"
  - "**/host.json"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs,py,cs,java}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/tests/**"
  - "**/node_modules/**"
  - "**/bin/**"
  - "**/obj/**"
preFilter:
  - regex: "\"authLevel\"\\s*:\\s*\"(anonymous|function)\""
    label: "function.json authLevel"
  - regex: "AuthorizationLevel\\.(Anonymous|Function|Admin)"
    label: "C# HttpTrigger AuthorizationLevel"
  - regex: "module\\.exports\\s*=\\s*async\\s+function\\s*\\(\\s*context\\s*,\\s*req"
    label: "JS Azure Function v1/v2 handler"
  - regex: "app\\.http\\s*\\(|app\\.timer\\s*\\(|app\\.queue\\s*\\(|app\\.serviceBusQueue\\s*\\("
    label: "JS Azure Functions v4 binding"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-285
  - OWASP-A05:2021
---

You are reviewing Azure Function implementations for the standard
set of security issues.

**Walker mode advantage:** the auth posture is split between
`function.json` (or the C# attribute) declaring `authLevel`, and the
handler body. Open both — `anonymous` is fine ONLY if the handler
does its own auth check. Also check sibling files for Key Vault
references in deploy config to assess whether secrets in
`process.env` are actually Vault-sourced.

## What to look for

**HTTP trigger with `authLevel: "anonymous"`:**
```json
// function.json
{
  "bindings": [{
    "type": "httpTrigger",
    "authLevel": "anonymous",
    "methods": ["post"]
  }]
}
```

```csharp
[FunctionName("Submit")]
public static async Task<IActionResult> Run(
  [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequest req)
```
`anonymous` = no function key required. Acceptable for public APIs
but the function body must enforce its own auth. If neither key nor
in-function auth is present, the endpoint is open.

**`authLevel: "function"` with key in URL:**
Function-level keys are stored in URL query strings, so they end up
in logs, browser history, referrer headers. Not great as a primary
auth mechanism — flag for review.

**Missing input validation:**
```ts
module.exports = async function (context, req) {
  const id = req.query.id;
  const row = await db.users.findUnique({ where: { id } });
  context.res = { body: row };
};
```

**Managed identity used without scope restriction:**
The function's system-assigned managed identity may have access to
many Azure resources. If the function delegates user actions, it
acts as the function — escalating user permissions to MI's scope.

**Secrets in app settings (env vars):**
Function app settings are visible to anyone with
`Microsoft.Web/sites/config/read`. Prefer Key Vault references:
```
"@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/Db/...)"
```

## True positive criteria

Flag when:
1. An HTTP-triggered function uses `authLevel: "anonymous"` AND the
   handler body does not perform its own auth check before
   sensitive operations.
2. The handler reads user input (query, body, headers) without
   schema validation.
3. The function uses a system-assigned managed identity to perform
   actions on behalf of the caller without checking the caller's
   authorization.
4. Secrets are read from `process.env.*` / `Environment.GetEnvironmentVariable`
   directly instead of via Key Vault references.

## What to ignore

- HTTP functions with `authLevel: "function"` or `"admin"` AND no
  particularly sensitive operations.
- Functions clearly behind Azure API Management with explicit
  policy-level auth.
- Test files.

## Examples

True positives:
```ts
// Anonymous trigger, no in-handler auth
module.exports = async function (context, req) {
  const userId = req.query.userId;
  context.res = { body: await db.users.findUnique({ where: { id: userId } }) };
};
```

```csharp
[FunctionName("GetUser")]
public static async Task<IActionResult> Run(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "users/{id}")] HttpRequest req,
    string id)
{
    return new OkObjectResult(await _db.GetUser(id));
}
```

False positives to skip:
```ts
// Anonymous, but handler enforces auth
module.exports = async function (context, req) {
  const token = req.headers["authorization"];
  const user = await verifyToken(token);
  if (!user) {
    context.res = { status: 401, body: "unauthorized" };
    return;
  }
  // ...
};
```
