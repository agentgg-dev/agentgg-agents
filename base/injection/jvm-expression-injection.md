---
slug: jvm-expression-injection
name: Expression Language Injection (JVM)
description: 'Java expression engines (commons-jxpath, Spring SpEL, OGNL, Apache JEXL, MVEL) invoked with user-controlled input as the expression string — allows arbitrary code execution by evaluating attacker-supplied expressions against server-side objects.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'JXPathContext\.(newContext|compile)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: commons-jxpath JXPathContext usage
      - regex: 'SpelExpressionParser\s*\(\)|ExpressionParser\s+\w+\s*='
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Spring SpEL expression parser
      - regex: 'Ognl\.(getValue|parseExpression|compileExpression)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: OGNL expression evaluation
      - regex: 'MVEL\.(eval|evalToString|compileExpression|executeExpression)\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: MVEL eval
      - regex: '(JexlEngine|JexlBuilder)\s*\(\)|\.createExpression\s*\(|\.createScript\s*\('
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Apache JEXL expression or script creation
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
    - regex: 'JXPathContext\.(newContext|compile)\s*\('
      label: commons-jxpath JXPathContext usage
    - regex: 'SpelExpressionParser\s*\(\)|parseExpression\s*\('
      label: Spring SpEL expression parser
    - regex: 'Ognl\.(getValue|parseExpression|compileExpression)\s*\('
      label: OGNL expression evaluation
    - regex: 'MVEL\.(eval|evalToString|compileExpression|executeExpression)\s*\('
      label: MVEL eval
    - regex: '(JexlEngine|JexlBuilder)\s*\(\)|\.createExpression\s*\(|\.createScript\s*\('
      label: Apache JEXL expression or script creation
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-94
  - CWE-917
  - 'OWASP-A03:2021'
---

You are reviewing JVM source code (Java / Kotlin) for expression language
injection — user-controlled input passed as the expression string to a
Java expression engine that can navigate object graphs and invoke arbitrary
methods, allowing an attacker to execute code on the server.

Unlike XPath injection (which manipulates an XML query), these engines
evaluate expressions against live Java objects and can call any accessible
method, read static fields, or instantiate classes. The root cause is the
same: the expression string is treated as trusted code when it is not.

**Cross-file analysis:** the expression string often originates in a
request handler (OGC parameter, REST body field, form input) and is passed
through a service or utility several hops before reaching the engine.
Trace the value: a variable named `propertyName`, `filter`, or `xpath`
may be `request.getParameter("propertyName")` after one level of
indirection. Open callers to confirm whether the value crosses a trust
boundary before it reaches the expression engine.

## What to look for

**commons-jxpath (JXPathContext):**
```java
JXPathContext ctx = JXPathContext.newContext(featureObject);
Object value = ctx.getValue(propertyName);          // propertyName from request
Iterator it  = ctx.iterate(userExpression);
List     sel = ctx.selectNodes(userFilter);
```
JXPath evaluates XPath-like expressions that can call Java methods via
`function:methodName(args)` syntax. Any user-controlled expression can
execute arbitrary Java methods visible on the context object.

**Spring SpEL (SpelExpressionParser):**
```java
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(userInput);     // user-controlled
Object result = expr.getValue(context);
```
SpEL can navigate the entire Spring context, access beans, and invoke
methods: `T(java.lang.Runtime).getRuntime().exec('id')`.

**OGNL:**
```java
Object tree = Ognl.parseExpression(userInput);
Object result = Ognl.getValue(tree, ognlContext, root);
// or combined:
Object result = Ognl.getValue(userInput, context, root);
```
OGNL can call static methods, access class loaders, and chain reflective
calls. Classic Struts2 RCE vectors used this path.

**MVEL:**
```java
Object result = MVEL.eval(userInput, vars);
Object result = MVEL.evalToString(userInput, context);
Serializable compiled = MVEL.compileExpression(userInput);
```

**Apache JEXL:**
```java
JexlEngine jexl = new JexlBuilder().create();
JexlExpression e = jexl.createExpression(userInput);
Object result = e.evaluate(jexlContext);
JexlScript script = jexl.createScript(userInput);
script.execute(jexlContext);
```

## True positive criteria

Flag when ALL of the following hold:

1. One of the engine APIs above is called with an expression/source argument.
2. The argument is traceable to user-controlled input — a request
   parameter, path segment, POST body field, header, or a value read from
   a user-writable store — rather than a hardcoded constant.
3. No strict allowlist is enforced before the expression reaches the
   engine. An allowlist must validate the exact string against a set of
   known-safe identifiers (e.g. `^[a-zA-Z_][a-zA-Z0-9_.]*$` AND checked
   against an explicit whitelist). A type-check or length limit alone is
   not sufficient.

## What to ignore

- Hardcoded expression strings: `ctx.getValue("./name")`, `parser.parseExpression("user.age")`.
  The expression is a compile-time constant; no injection is possible.
- Values sourced from a server-controlled configuration file or database
  column that users cannot write to.
- Tests under `src/test/`.
- Expression engines running in a fully sandboxed mode with a documented,
  tested allow-list of permitted operations that excludes method invocation
  and class access (rare — verify the sandbox configuration is actually applied).

## Examples

True positives:
```java
// commons-jxpath with OGC request parameter
String propertyName = request.getParameter("propertyName");
JXPathContext ctx = JXPathContext.newContext(feature);
Object value = ctx.getValue(propertyName);           // RCE via jxpath function syntax

// Spring SpEL with REST body field
String expr = body.getFilter();                      // user-supplied
parser.parseExpression(expr).getValue(appContext);   // can access any bean/class

// OGNL with URL parameter
String expression = req.getParameter("expr");
Ognl.getValue(expression, ognlContext, root);        // classic Struts2 pattern
```

False positives to skip:
```java
// Constant expression — no injection
JXPathContext ctx = JXPathContext.newContext(obj);
ctx.getValue("//feature[@id='1']/name");

// SpEL with server-controlled template (not request-derived)
parser.parseExpression(appConfig.getExpressionTemplate()).getValue(ctx);

// Property name validated against strict allowlist
if (!ALLOWED_PROPERTIES.contains(name) || !name.matches("^[a-zA-Z_]\\w*$")) {
    throw new SecurityException("invalid property");
}
ctx.getValue(name);
```

If the expression string is built from or set to a request-derived value
with no strict allowlist check on the exact characters, treat it as a
finding. The burden is on the code to prove the value cannot contain
expression metacharacters.
