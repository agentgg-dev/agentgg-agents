---
slug: electron-node-integration
name: Electron nodeIntegration Enabled
description: 'Electron BrowserWindow or webview created with nodeIntegration:true — any XSS in the renderer process can call require() and execute arbitrary OS commands with the privileges of the desktop application.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'nodeIntegration\s*:\s*true'
        in:
          - '**/*.{js,ts,mjs,cjs}'
        notIn:
          - '**/node_modules/**'
          - '**/dist/**'
        label: nodeIntegration enabled in Electron config
where:
  extensions:
    - js
    - ts
    - mjs
    - cjs
  excludePatterns:
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/*.test.{js,ts}'
    - '**/*.spec.{js,ts}'
  preFilter:
    - regex: 'nodeIntegration\s*:\s*true'
      label: nodeIntegration enabled
    - regex: 'contextIsolation\s*:\s*false'
      label: contextIsolation disabled
    - regex: 'new\s+BrowserWindow\s*\('
      label: BrowserWindow instantiation
    - regex: '<webview[^>]+nodeintegration'
      label: webview with nodeintegration attribute
references:
  - CWE-79
  - CWE-94
  - 'OWASP-A05:2021'
---

You are reviewing Electron application source code for `nodeIntegration: true` — a configuration that enables the renderer process to call Node.js APIs including `require('child_process')`. Any XSS in the renderer escalates to arbitrary OS command execution.

## The vulnerability chain

In Electron, the renderer process displays web content. With `nodeIntegration: true`:
1. JavaScript in the renderer can call `require('child_process').exec('cmd')`
2. Any XSS in the rendered page becomes Remote Code Execution on the victim's machine
3. The attacker gains the full OS privileges of the user running the desktop app

## Vulnerable patterns

```js
// BrowserWindow with nodeIntegration
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,      // VULNERABLE
    contextIsolation: false,    // makes it worse — no isolation barrier
  }
});
win.loadURL('https://external-site.com');  // loads remote content — critical
```

```html
<!-- webview tag -->
<webview src="https://external-site.com" nodeintegration></webview>
```

## Risk levels

**Critical:** `nodeIntegration: true` + loads remote content (`loadURL` with an http/https URL, or `loadFile` with user-controlled path). Any content injection on the remote page becomes RCE.

**High:** `nodeIntegration: true` + loads local files (`loadFile`) but the local content processes external data (e.g., renders user-supplied markdown, fetches and displays third-party content, renders webview iframes).

**Medium:** `nodeIntegration: true` + loads only fully hardcoded local content with no external data rendered.

## The contextIsolation relationship

`contextIsolation: true` (the default since Electron 12) adds a barrier between the renderer's JavaScript world and the preload script's Node.js world. With `contextIsolation: false` AND `nodeIntegration: true`, no barrier exists — `require` is directly available in the page's JavaScript.

With `contextIsolation: true` AND `nodeIntegration: true`, the page cannot directly call `require`, but the preload script can expose Node APIs via `contextBridge.exposeInMainWorld()` — check the preload script for what is exposed.

## Cross-file analysis

1. Find the `BrowserWindow` constructor — check `webPreferences` for `nodeIntegration` and `contextIsolation`
2. Find `win.loadURL()` or `win.loadFile()` — determines whether remote content is loaded
3. If `contextIsolation: true`, find the preload script and check what `contextBridge.exposeInMainWorld()` exposes — overly broad exposure is a secondary issue
4. Look for `<webview>` tags in HTML/JSX — each is a separate renderer context

## What to ignore

- `nodeIntegration: false` (explicit opt-out, safe)
- Electron apps where `contextIsolation: true` AND the preload only exposes a narrow IPC bridge (not raw `require` or `exec`)
- `nodeIntegration: true` in test harnesses under `__tests__/` that don't ship in the production build

## Remediation pattern

```js
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,   // disable
    contextIsolation: true,   // enable isolation (default since Electron 12)
    preload: path.join(__dirname, 'preload.js'),  // use IPC bridge instead
  }
});
```

## Examples

True positives:
```js
new BrowserWindow({
  webPreferences: { nodeIntegration: true, contextIsolation: false }
}).loadURL('https://app.example.com');
// Remote content + full Node.js access = RCE via XSS
```

False positives to skip:
```js
new BrowserWindow({
  webPreferences: { nodeIntegration: false, contextIsolation: true, preload: './preload.js' }
});
```

Report the `nodeIntegration` value, `contextIsolation` value, what content is loaded (remote URL vs local file), and what the preload script exposes if `contextIsolation` is true.
