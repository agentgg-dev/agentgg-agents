---
slug: websocket-auth-origin
name: WebSocket Handshake Missing Auth / Origin Check
description: 'WebSocket upgrade/connection handlers that accept connections without verifying a session/token and without checking the Origin header against an allowlist — enabling Cross-Site WebSocket Hijacking (CSWSH) and unauthenticated access. Follows verifyClient / interceptor helpers across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'new\s+WebSocket\.?Server\s*\(|new\s+WebSocketServer\s*\(|require\(\s*[''"]ws[''"]\s*\)|from\s+[''"]ws[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Node ws server
      - regex: 'socket\.io|new\s+Server\s*\([^)]*\)|io\s*\.\s*on\s*\(\s*[''"]connection[''"]'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: socket.io server
      - regex: '@app\.websocket|WebSocketEndpoint|async\s+def\s+\w+\s*\([^)]*WebSocket|import\s+websockets|websockets\.serve\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
          - '**/vendor/**'
        label: Python websockets / FastAPI websocket
      - regex: 'implements\s+WebSocketHandler|extends\s+(Text|Binary|Abstract)?WebSocketHandler|registerWebSocketHandlers|@ServerEndpoint'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/test/**'
          - '**/vendor/**'
        label: Spring / JSR-356 WebSocket handler
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
    - py
    - java
    - kt
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/*_test.go'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'new\s+WebSocket\.?Server\s*\(|new\s+WebSocketServer\s*\(|\.on\s*\(\s*[''"](connection|upgrade)[''"]'
      label: Node ws connection/upgrade handler
    - regex: 'verifyClient|handleUpgrade|allowRequest|noServer\s*:\s*true'
      label: ws/socket.io upgrade gate
    - regex: 'io\s*\.\s*on\s*\(\s*[''"]connection[''"]|io\s*\.\s*use\s*\('
      label: socket.io connection handler / middleware
    - regex: '@app\.websocket|WebSocketEndpoint|websockets\.serve\s*\(|await\s+\w+\.accept\s*\('
      label: Python websocket accept
    - regex: 'WebSocketHandler|@ServerEndpoint|HandshakeInterceptor|registerStompEndpoints|addHandler\s*\('
      label: Java/Kotlin WebSocket handler/interceptor
references:
  - CWE-346
  - CWE-1385
  - 'OWASP-A01:2021'
---

You are reviewing server-side code for WebSocket handshakes that accept
connections without authentication and/or without validating the
`Origin` header — letting an attacker mount Cross-Site WebSocket
Hijacking (CSWSH) or simply connect as an unauthenticated client.

A WebSocket upgrade is a normal HTTP `GET` that browsers send WITHOUT
the Same-Origin Policy and (for cookies) WITHOUT CORS protection — the
browser attaches the victim's cookies automatically. If the server
authenticates the socket purely via the session cookie and never checks
`Origin`, any web page the victim visits can open `wss://your-app/...`
in the background and ride the victim's session. If the server requires
no auth at all, anyone on the internet can connect.

**Cross-file analysis:** the auth/origin check is frequently NOT inline
in the `connection` handler. Trace these hops before concluding a
finding:
- Node `ws`: a `verifyClient` function, an `upgrade` listener that calls
  `wss.handleUpgrade(...)`, or `noServer: true` wired to an external
  `server.on('upgrade', ...)` that authenticates first. Open the
  `createServer`/`http.Server` upgrade handler.
- `socket.io`: `io.use((socket, next) => ...)` middleware, or an
  `allowRequest` option passed to the `Server` constructor.
- FastAPI/`websockets`: a dependency (`Depends(...)`), a decorator, or a
  manual token read before `await websocket.accept()`.
- Spring: a `HandshakeInterceptor` / `setAllowedOrigins(...)` registered
  in the `WebSocketConfigurer`, not in the handler itself. Open the
  config class.

## What to look for

**Node `ws` with no verifyClient and no origin check:**
```js
const wss = new WebSocketServer({ server });
wss.on("connection", (socket, req) => {
  socket.on("message", (m) => handle(socket, m));
});
```
No `verifyClient`, the `upgrade` is not gated, and `req.headers.origin`
is never compared to an allowlist.

**verifyClient that is trivially true:**
```js
const wss = new WebSocketServer({
  verifyClient: (info, cb) => cb(true),
});
```
Returning `true` unconditionally (or `verifyClient: () => true`) is the
same as no check.

**socket.io with no middleware and CORS wide open:**
```js
const io = new Server(server, { cors: { origin: "*" } });
io.on("connection", (socket) => { ... });
```
`cors: { origin: "*" }` plus no `io.use(...)` auth middleware.

**FastAPI / `websockets` accepting without auth:**
```py
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
```
No token read from query/header/cookie, no `Depends` guard, no origin
validation before `accept()`.

**Spring handler with no interceptor / allowed origins `*`:**
```java
registry.addHandler(new ChatHandler(), "/ws").setAllowedOrigins("*");
```
`setAllowedOrigins("*")` disables the origin check; absence of any
`HandshakeInterceptor` that authenticates means anyone can connect.

## True positive criteria

You must be able to name the attacker and the trust boundary. Flag when
BOTH of these hold (the burden is on the code to show safety):

1. The handshake/connection handler does NOT establish identity: no
   session/token/API-key is read and validated before the socket is
   accepted (directly, or in a verifyClient / middleware / interceptor /
   dependency a few hops away), AND
2. The handler does NOT validate the `Origin` header against an
   allowlist (no `verifyClient` origin check, no `allowRequest`, no
   `setAllowedOrigins(specificOrigins)`, no manual `origin ===` compare).

Concretely:
- If auth is cookie-based AND there is no Origin allowlist → CSWSH. The
  attacker is "any website the victim opens"; the trust boundary is the
  cross-origin browser request carrying the victim's cookie. I can host
  a page that opens a socket to your app as the logged-in victim.
- If there is no auth at all → unauthenticated access. The attacker is
  "anyone who can reach the port"; I can connect directly with a
  WebSocket client.

## What to ignore

- Handlers behind a real `verifyClient`/middleware/interceptor that
  reads and verifies a token or session before accepting, AND either
  the auth is a bearer token in a custom header (not a cookie, so CSWSH
  does not apply) or an Origin allowlist is enforced.
- `setAllowedOrigins("https://app.example.com")` /
  `cors: { origin: ["https://app.example.com"] }` with a fixed list.
- Internal-only sockets not exposed to browsers: a `ws` server bound to
  `127.0.0.1`/a unix socket, IPC/stdio transports, or worker-to-worker
  channels inside a cluster — there is no cross-origin browser and no
  internet exposure.
- Sockets that carry only public, non-sensitive, read-only broadcast
  data and perform no per-user action (e.g. an anonymous public
  ticker). No session is riding the connection.
- A token validated from a query param or a subprotocol
  (`Sec-WebSocket-Protocol`) before `accept()` — that is not cookie
  auth, so CSWSH does not apply; do not flag for missing Origin alone.

## Examples

True positives:
```js
// ws: cookie-authenticated downstream, no verifyClient, no origin check
const wss = new WebSocketServer({ server });
wss.on("connection", (socket, req) => {
  const user = sessionFromCookie(req.headers.cookie);
  socket.on("message", (m) => doPrivilegedThing(user, m));
});

// socket.io: no auth middleware, origin wide open
const io = new Server(server, { cors: { origin: "*" } });
io.on("connection", (s) => s.on("order", placeOrder));
```
```py
@app.websocket("/notifications")
async def ws(websocket: WebSocket):
    await websocket.accept()
    await stream_user_notifications(websocket)
```

False positives to skip:
```js
// Token verified before accept; bearer (not cookie) -> no CSWSH
const wss = new WebSocketServer({
  verifyClient: (info, cb) => {
    const tok = new URL(info.req.url, "http://x").searchParams.get("token");
    verify(tok).then((ok) => cb(ok));
  },
});

// socket.io middleware auth + fixed origin
const io = new Server(server, { cors: { origin: ["https://app.example.com"] } });
io.use((socket, next) => (verify(socket.handshake.auth.token) ? next() : next(new Error("unauth"))));
```
```java
// Origin allowlist + handshake interceptor that authenticates
registry.addHandler(new ChatHandler(), "/ws")
        .addInterceptors(new AuthHandshakeInterceptor())
        .setAllowedOrigins("https://app.example.com");
```
