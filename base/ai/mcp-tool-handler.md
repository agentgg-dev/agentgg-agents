---
slug: mcp-tool-handler
name: MCP Tool Handler Security
description: MCP (Model Context Protocol) server tool handlers — verify per-tool authentication, argument validation, and capability scoping. Walker mode follows tool execute helpers and server bootstrap.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
outputType: finding
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs}"
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/.next/**"
preFilter:
  - regex: "from\\s+['\"]@modelcontextprotocol/sdk"
    label: "Imports MCP SDK"
  - regex: "server\\.tool\\s*\\(|\\bsetRequestHandler\\s*\\(\\s*CallToolRequestSchema|registerTool\\s*\\("
    label: "MCP tool registration"
  - regex: "new\\s+(StdioServerTransport|SSEServerTransport|HttpServerTransport)\\s*\\("
    label: "MCP transport instantiation (verify auth on HTTP/SSE)"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-285
  - OWASP-LLM06
---

You are reviewing MCP (Model Context Protocol) server tool handlers
for missing authentication and input validation.

**Walker mode advantage:** an MCP server's auth posture depends on
its transport (stdio = local user is the boundary; HTTP/SSE = needs
explicit auth). Find the server bootstrap file and check which
transport is in use. Tool `execute` bodies may delegate to shared
helpers — open them to confirm capability scoping and arg
validation. A tool that calls `runShell` looks tame in registration
but isn't. MCP servers expose
tools to LLM clients (Claude Desktop, custom agents); a poorly
secured tool is a foothold the LLM can use against the host.

## What to look for

**MCP server tool registration:**
```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";
server.tool("read_file", schema, async (args) => ({ ... }));
registerTool(server, { name: "exec" });
server.setRequestHandler(CallToolRequestSchema, async (req) => ({ ... }));
```

**Concerns to review per tool:**

1. **Authentication:** Does the MCP server require auth to connect?
   For stdio servers running locally, the user IS the auth boundary.
   For HTTP/SSE servers, an unauthenticated connection means anyone
   on the network can invoke tools.

2. **Argument validation:** Are arguments validated against a strict
   Zod / JSON Schema before use? The LLM-supplied args are
   effectively a prompt-injection-controlled value.

3. **Capability scoping:** Does the tool only access what it
   advertises? A `read_file` tool should be confined to a specific
   directory tree; a `send_email` tool should validate recipient
   against an allowlist.

4. **Side-effect tools:** Write / delete / network / spawn tools
   need extra care — what they do is more impactful than read tools.

5. **Output sanitization:** If the tool's output is fed back to the
   LLM, untrusted external data (web fetch results, file contents)
   should be wrapped so the LLM doesn't follow instructions in it.

## True positive criteria

Flag every MCP tool registration for review when:
1. The tool body performs side effects (file write, network egress,
   shell exec, DB write).
2. No argument validation occurs before the side effect.
3. The server has no auth layer (HTTP/SSE MCP server without auth,
   or stdio with security-sensitive capabilities).

## What to ignore

- Read-only tools with limited scope (read from a single project
  directory).
- Tools that delegate to a vetted library with its own auth
  (e.g., a `query_db` tool that uses the user's DB credentials).
- Test files.

## Examples

True positives:
```ts
// Tool that runs arbitrary commands, no validation
server.tool("execute", z.object({ cmd: z.string() }), async ({ cmd }) => {
  const { stdout } = await exec(cmd);
  return { content: [{ type: "text", text: stdout }] };
});

// HTTP MCP server with no auth
const httpServer = http.createServer(async (req, res) => {
  // No auth check
  await mcp.handleRequest(req, res);
});
httpServer.listen(8080);
```

False positives to skip:
```ts
// Scoped read tool
server.tool(
  "read_project_file",
  z.object({ relativePath: z.string().regex(/^[a-zA-Z0-9._/-]+$/) }),
  async ({ relativePath }) => {
    const absPath = path.resolve(PROJECT_ROOT, relativePath);
    if (!absPath.startsWith(PROJECT_ROOT + path.sep)) {
      throw new Error("outside project");
    }
    return { content: [{ type: "text", text: await fs.readFile(absPath, "utf8") }] };
  }
);
```
