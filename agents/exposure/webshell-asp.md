---
slug: webshell-asp
name: ASP/ASPX Webshell Detection
description: 'ASP and ASPX webshell indicators: eval/execute with user input, WScript.Shell instantiation, cmd.exe references, and ExecuteStatement calls in .asp, .aspx, .ashx, .asmx files — backdoor scripts enabling remote command execution via HTTP.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '(?i)(?:wscript\.shell|cmd\.exe|ExecuteStatement|mmshell|GetCmd)'
        in:
          - '**/*.{asp,asa,aspx,ashx,asmx,asax}'
        notIn:
          - '**/obj/**'
          - '**/bin/**'
        label: ASP webshell signature present
where:
  extensions:
    - asp
    - asa
    - aspx
    - ashx
    - asmx
    - asax
  excludePatterns:
    - '**/obj/**'
    - '**/bin/**'
    - '**/node_modules/**'
  preFilter:
    - regex: '(?i)\b(?:eval|execute)\s*\('
      label: eval/execute call in ASP
    - regex: '(?i)wscript\.shell'
      label: WScript.Shell — allows OS command execution
    - regex: '(?i)ExecuteStatement\s*\('
      label: ExecuteStatement call
    - regex: '(?i)cmd\.exe'
      label: cmd.exe reference
    - regex: '(?i)mmshell|GetCmd'
      label: Known ASP webshell keyword
references:
  - CWE-506
  - CWE-94
---

You are reviewing ASP and ASPX files for webshell indicators — backdoor scripts that allow remote command execution via HTTP requests.

## ASP classic webshell patterns

### eval / execute with user input — critical

Classic ASP's `eval()` and `execute()` evaluate strings as VBScript code:
```asp
eval(Request.QueryString("cmd"))
execute(Request.Form("x"))
ExecuteStatement(Request("c"))
```

### WScript.Shell — critical

Creates a shell object allowing OS command execution:
```asp
Set shell = CreateObject("WScript.Shell")
shell.Run(Request.QueryString("cmd"))

Set oShell = Server.CreateObject("WScript.Shell")
oShell.Exec("cmd.exe /c " & Request.Form("command"))
```

### cmd.exe references

Direct cmd.exe invocation in ASP code is a strong webshell indicator:
```asp
Response.Write CreateObject("WScript.Shell").Exec("cmd /c " & Request("c")).StdOut.ReadAll
```

### ExecuteStatement

```asp
ExecuteStatement(Request.QueryString("code"))
```

### Known webshell markers

- `mmshell` — a specific ASP webshell family name
- `GetCmd` — function name commonly found in ASP webshells

## ASPX webshell patterns

ASPX webshells often use .NET reflection or code compilation:
```aspx
<%@ Page Language="C#" %>
<% 
System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]);
%>
```

## True positive criteria

Flag at critical:
1. `eval()`/`execute()`/`ExecuteStatement()` receiving request parameters
2. `WScript.Shell` combined with request data passed to Run/Exec
3. `cmd.exe` in the command string built from user input

Flag at high:
4. `WScript.Shell` instantiation even without obvious request data — investigate what arguments are passed to Run/Exec
5. Known webshell keywords (`mmshell`, `GetCmd`)

## Context

Check whether the file:
- Is in an uploads or writable directory (very suspicious — indicates the file was dropped at runtime)
- Has a creation date inconsistent with other application files
- Has no surrounding application code (standalone file, no imports, no class structure)

Report: the specific pattern found, the file path and directory context, and whether the file appears to be a legitimate application page or a standalone backdoor.
