---
slug: script-engine-dos
name: Denial of Service via Unbounded Script Execution
description: 'Script or expression engines (javax.script, Groovy, GraalVM, Jiffle, Rhino/Nashorn) executing user-controlled script source without an iteration limit or execution timeout — allows an attacker to trigger an infinite loop and exhaust server threads or CPU, causing denial of service.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'ScriptEngineManager\s*\(\)|ScriptEngine\s+\w+\s*='
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: javax.script ScriptEngine usage
      - regex: 'GroovyShell\s*\(\s*\)|groovyShell\.(evaluate|run|parse)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: GroovyShell evaluate/run
      - regex: 'new\s+GroovyClassLoader\s*\(\)|GroovyClassLoader\s*\(\s*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: GroovyClassLoader compiling user script
      - regex: 'import\s+org\.graalvm\.polyglot|org\.graalvm\.polyglot\.Context'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: GraalVM Polyglot Context import
      - regex: 'new\s+Jiffle\s*\(|JiffleRuntime\s*\(\s*\)|jiffle\.(getRuntime|setScript)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Jiffle map algebra script engine
      - regex: 'ScriptRunner\s*\(\s*\)|engine\s*\.\s*eval\s*\(\s*[^")][^)]*\)'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Generic script engine eval with variable
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
    - regex: 'ScriptEngineManager\s*\(\)|ScriptEngine\s+\w+\s*='
      label: javax.script ScriptEngine usage
    - regex: 'GroovyShell\s*\(\s*\)|groovyShell\.(evaluate|run|parse)\s*\('
      label: GroovyShell evaluate/run
    - regex: 'new\s+GroovyClassLoader\s*\(\)|GroovyClassLoader\s*\(\s*\)'
      label: GroovyClassLoader compiling user script
    - regex: 'import\s+org\.graalvm\.polyglot|org\.graalvm\.polyglot\.Context'
      label: GraalVM Polyglot Context import
    - regex: 'new\s+Jiffle\s*\(|JiffleRuntime\s*\(\s*\)|jiffle\.(getRuntime|setScript)\s*\('
      label: Jiffle map algebra script engine
    - regex: 'ScriptRunner\s*\(\s*\)|engine\s*\.\s*eval\s*\(\s*[^")][^)]*\)'
      label: Generic script engine eval with variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-400
  - CWE-835
  - 'OWASP-A05:2021'
---

You are reviewing JVM source code (Java / Kotlin) for denial-of-service
via unbounded script execution — a script or expression engine that accepts
user-controlled script source and executes it without an iteration limit,
step count, or timeout watchdog.

This differs from eval injection (where the goal is code execution): here
the engine is legitimately designed to run user scripts (map algebra,
WPS processes, dynamic styling rules), but lacks the guardrail that would
abort a script that loops forever. A single malicious request with an
infinite loop consumes a server thread indefinitely, and enough concurrent
requests exhaust the thread pool, causing a denial of service.

**Key question:** is the script SOURCE (not just the data fed to a fixed
script) user-controlled, AND does the engine execute it without a mechanism
to abort after a maximum number of iterations or after a wall-clock timeout?

## What to look for

**javax.script.ScriptEngine (Nashorn, Rhino, GraalJS via JSR-223):**
```java
ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
engine.eval(userScript);     // no timeout — hangs if userScript loops forever
```

**Groovy:**
```java
GroovyShell shell = new GroovyShell();
shell.evaluate(userScript);  // no SecureASTCustomizer step limit

GroovyClassLoader gcl = new GroovyClassLoader();
Class cls = gcl.parseClass(userScript);
Script s = (Script) cls.newInstance();
s.run();                     // no loop guard
```

**GraalVM Polyglot:**
```java
try (Context context = Context.create()) {
    context.eval("js", userScript);   // no ResourceLimits set
}
// Safe form uses ResourceLimits:
// Context.newBuilder().resourceLimits(ResourceLimits.newBuilder().statementLimit(10_000, ...).build()).build()
```

**Jiffle map algebra (jai-ext / GeoTools):**
```java
Jiffle jiffle = new Jiffle();
jiffle.setScript(userJiffleScript);  // script source from WMS/WPS request
jiffle.compile();
JiffleRuntime runtime = jiffle.getRuntimeInstance();
runtime.run();               // no iteration cap — while(true) {} hangs thread
```

**Missing safeguards to look for:**
- No `ExecutorService.submit(...).get(timeoutSeconds, TimeUnit.SECONDS)` wrapping the eval.
- No `Thread.interrupt()` via a watchdog thread.
- Groovy: no `SecureASTCustomizer` with a `maximumIterations` limit or
  `ThreadInterrupt` AST transformation applied to the compilation.
- GraalVM: no `ResourceLimits.newBuilder().statementLimit(...)` applied to the Context.
- Jiffle: no equivalent step/iteration counter (the engine itself lacked this until patched).

## True positive criteria

Flag when ALL of the following hold:

1. A script engine executes script SOURCE that is, or can be, user-controlled:
   the script text comes from a request parameter, POST body, user-authored
   WPS/WMS style rule, uploaded template, or database record the user can write.
2. The execution is NOT wrapped in a timeout mechanism: no `Future.get(n, SECONDS)`,
   no watchdog thread calling `thread.interrupt()` after a deadline.
3. The engine does NOT have a native step/iteration limit configured (Graal
   `ResourceLimits`, Groovy `SecureASTCustomizer` with `maximumIterations`,
   a custom `ScriptContext` with quota enforcement).

You must be able to say: "I am an unauthenticated (or authenticated) caller;
I send a script containing `while(true){}` (or Jiffle `while(true){n=n+1;}`);
the request thread blocks indefinitely."

## What to ignore

- Script engines executing FIXED scripts loaded from classpath or config files
  that users cannot modify. Only the script SOURCE being user-controlled is in scope.
- Evals of constant strings or expressions: `engine.eval("1 + 1")`.
- Execution wrapped in a properly configured timeout:
  ```java
  Future<Object> f = executor.submit(() -> engine.eval(userScript));
  try { return f.get(5, TimeUnit.SECONDS); }
  catch (TimeoutException e) { f.cancel(true); throw new ServiceException("timeout"); }
  ```
- Tests under `src/test/`.
- Build-time code generation or developer tooling that doesn't serve user requests.

## Examples

True positives:
```java
// Jiffle from WMS dynamic style — no iteration limit
String jiffleScript = styleRule.getTransformationScript();  // user-authored
Jiffle jiffle = new Jiffle(jiffleScript, outputBandNames);
jiffle.getRuntimeInstance().evaluateAll(null);              // hangs on infinite loop

// GroovyShell without step limit
String script = request.getParameter("script");
GroovyShell shell = new GroovyShell();
shell.evaluate(script);                                     // while(true){} hangs thread

// javax.script without timeout
engine.eval(request.getParameter("expression"));
```

False positives to skip:
```java
// Timeout-wrapped eval
ExecutorService exec = Executors.newSingleThreadExecutor();
Future<Object> future = exec.submit(() -> engine.eval(userScript));
return future.get(MAX_EVAL_MILLIS, TimeUnit.MILLISECONDS);

// GraalVM with statement limit
Context ctx = Context.newBuilder("js")
    .resourceLimits(ResourceLimits.newBuilder().statementLimit(50_000, null).build())
    .build();
ctx.eval("js", userScript);

// Fixed script — user supplies only data, not the script text
engine.put("input", request.getParameter("value"));
engine.eval(FIXED_SCRIPT_FROM_CLASSPATH);   // script source is constant
```

If the script source crosses a trust boundary and the execution lacks both
a timeout and a native step limit, treat it as a finding. Report the
missing safeguard specifically so the fix is clear.
