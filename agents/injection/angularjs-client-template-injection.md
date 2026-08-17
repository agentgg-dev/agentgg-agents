---
slug: angularjs-client-template-injection
name: AngularJS Client-Side Template Injection (CSTI)
description: 'AngularJS (1.x) sinks that evaluate a string as an Angular expression/template — $compile, $interpolate, $parse, scope.$eval, $sce.trustAsHtml, ng-bind-html — where the string carries untrusted input. Because AngularJS evaluates {{ }} expressions, HTML-encoding does NOT mitigate this; reflected content that looks inert executes as code. Distinct from the xss agent, which treats AngularJS {{ }} as safe. Traces the compiled/interpolated value to its origin and checks $sce trust.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'angular\.module\s*\('
        in:
          - '**/*.{js,ts,html,htm}'
        notIn:
          - '**/node_modules/**'
          - '**/bower_components/**'
          - '**/dist/**'
          - '**/*.min.js'
          - '**/__tests__/**'
          - '**/*.spec.{js,ts}'
        label: AngularJS angular.module() bootstrap
      - regex: 'ng-app\b|data-ng-app\b'
        in:
          - '**/*.{html,htm,js}'
        notIn:
          - '**/node_modules/**'
          - '**/bower_components/**'
          - '**/dist/**'
        label: ng-app application directive
      - regex: '["'']angular(js|\.js|-route|-sanitize|-cookies)?["'']\s*:'
        in:
          - '**/package.json'
          - '**/bower.json'
        label: AngularJS dependency declared
      - regex: '\$compile\b|\$interpolate\b|\$sce\b|\$parse\b'
        in:
          - '**/*.{js,ts}'
        notIn:
          - '**/node_modules/**'
          - '**/bower_components/**'
          - '**/dist/**'
          - '**/*.min.js'
          - '**/__tests__/**'
          - '**/*.spec.{js,ts}'
        label: AngularJS expression services injected
  prompt: |
    Run only if this project uses AngularJS (the 1.x framework:
    angular.js, angular.module(), ng-app, $scope, $compile, $sce). Do
    NOT run for Angular 2+ (@angular/core, @Component, standalone
    components) alone, nor for React/Vue projects — client-side template
    injection here is specific to AngularJS's runtime evaluation of
    {{ }} expressions.
where:
  extensions:
    - js
    - ts
    - html
    - htm
  excludePatterns:
    - '**/node_modules/**'
    - '**/bower_components/**'
    - '**/dist/**'
    - '**/*.min.js'
    - '**/__tests__/**'
    - '**/*.spec.{js,ts}'
    - '**/test/**'
  preFilter:
    - regex: '\$compile\s*\(\s*[^''"\s)]'
      label: $compile() called with a non-literal argument
    - regex: '\$interpolate\s*\(\s*[^''"\s)]'
      label: $interpolate() called with a non-literal argument
    - regex: '\$parse\s*\(\s*[^''"\s)]'
      label: $parse() called with a non-literal argument
    - regex: '\.\$eval(Async)?\s*\(\s*[^''"\s)]'
      label: scope.$eval() called with a non-literal argument
    - regex: '\$sce\.trustAs(Html|Js|ResourceUrl|Css|Url)?\s*\('
      label: $sce.trustAs* SCE bypass
    - regex: 'ng-bind-html\s*='
      label: ng-bind-html binding
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-1336
  - CWE-79
  - 'OWASP-A03:2021'
---

You are reviewing AngularJS (1.x) source for **client-side template
injection (CSTI)** — untrusted input that reaches an AngularJS sink
which evaluates it as an *expression* or *template*, not as inert text.
Once AngularJS interpolates `{{ ... }}` in attacker-controlled content,
the attacker runs JavaScript in the victim's session (CWE-1336 / CWE-79).

## The insight that regular XSS review misses

The generic `xss` agent explicitly treats AngularJS `{{ value }}` as
**safe**, because Angular HTML-encodes bound *data*. That is true for
DATA binding. CSTI is different: the untrusted string becomes part of
the **template that Angular compiles/interpolates**, so it is *evaluated*
before any encoding matters.

Consequently, **HTML-encoding does not mitigate CSTI.** A payload like
`{{constructor.constructor('alert(1)')()}}` or `{{7*7}}` contains no
`<`, `>`, or quotes, so a server that dutifully HTML-encodes its
reflected output still ships a live Angular expression. Do not treat
"the value is HTML-escaped" as a reason to dismiss a finding here.

(AngularJS < 1.6 shipped an expression "sandbox" that was repeatedly
escaped and is not a security boundary; 1.6+ removed it entirely. In all
versions, evaluating attacker input as an expression is code execution.)

## Sinks to flag

**Expression / template evaluation of a string:**
```js
$compile(userHtml)(scope);          // compiles a STRING as a template
$interpolate(userStr)(scope);       // evaluates {{ }} in the string
$parse(userExpr)(scope);            // parses & evaluates an expression
scope.$eval(userExpr);              // evaluates an expression
$rootScope.$eval(req);              // same
```

**SCE trust bypass (AngularJS $sce, not Angular 2 DomSanitizer):**
```js
$sce.trustAsHtml(userInput);        // then bound with ng-bind-html
$sce.trustAs($sce.HTML, userInput);
```
`trustAsHtml` tells Angular the content is safe; if it contains
attacker markup or expressions and is rendered via `ng-bind-html`, it
executes.

**Templates:**
```html
<div ng-bind-html="model.body"></div>   <!-- with $sce.trustAsHtml(userInput) -->
```

**The reflected-into-Angular variant (the GeoNetwork error-page shape):**
A server (any language) reflects request data (path, query, headers)
into an HTML response that is itself an AngularJS app (`<body ng-app>`).
Even HTML-encoded, the reflected value sits inside the ng-app scope and
is interpolated. If you can see the client bootstraps Angular over a
region that server-side code fills with request input, flag it — and
note in `details` that encoding is not a fix.

## Cross-file analysis

- Trace the argument to `$compile` / `$interpolate` / `$parse` /
  `$eval` back to its origin. Flag only when it is (or contains) a
  **string** derived from untrusted input: `$location.search()`,
  `$location.hash()`, `$routeParams`, `$stateParams`, `location.*`,
  request/query/header data, a server-rendered value, or user-authored
  stored content.
- For `$sce.trustAsHtml(x)`, find where `x` comes from and where the
  result is bound (search for `ng-bind-html`). Trusted-then-bound
  untrusted content is the bug.
- Distinguish `$compile(element)` on a **DOM node / jqLite object**
  (the normal, safe directive pattern) from `$compile(someString)` on a
  string. Only the string form is CSTI.

## True positive criteria

Flag when ALL hold:

1. An AngularJS evaluation sink is present: `$compile`, `$interpolate`,
   `$parse`, `scope.$eval`/`$evalAsync`, `$sce.trustAs*` bound via
   `ng-bind-html`, or request data reflected into an `ng-app` region.
2. The evaluated/trusted value is, transitively, untrusted input (see
   origins above) as a **string** (not a DOM element).
3. No neutralization that actually stops expression evaluation — note
   that HTML-encoding, and `$sce` *trusting* the value, do NOT count.
   Stripping/escaping the `{{ }}` delimiters or `$interpolate` with a
   custom non-evaluating context would.

## What to ignore

- `$compile(element)` / `$compile(elem.contents())` where the argument
  is a DOM node or jqLite object, not a user string.
- `$compile`/`$interpolate`/`$parse` of a **constant** string literal
  or a developer-authored template file.
- `{{ value }}` data binding where `value` is bound as data (Angular
  encodes it) — that is the safe pattern, the inverse of this bug.
- `$sce.trustAsHtml` / `ng-bind-html` on constant or server-sanitized
  trusted content (e.g. DOMPurify output) with no `{{ }}` passthrough.
- `$parse`/`$eval` of a hardcoded expression string.
- Angular 2+ `DomSanitizer.bypassSecurityTrust*` — that is the `xss`
  agent's territory, not AngularJS CSTI.
- Test/fixture files.

## Examples

True positives:
```js
// query param compiled as a template
var tpl = $location.search().q;
element.html($compile(tpl)(scope));

// route param interpolated
$scope.msg = $interpolate($routeParams.name)($scope);

// user input trusted then bound
$scope.body = $sce.trustAsHtml(req.data.comment);   // <div ng-bind-html="body">
```
```html
<!-- server reflected the request path into an ng-app page (even encoded) -->
<body ng-app="app">
  Page not found: /geonetwork/{{reflectedPath}}   <!-- interpolated -->
</body>
```

False positives to skip:
```js
// DOM element compiled — normal directive pattern, not a string
$compile(element.contents())(scope);

// constant template
$compile('<my-widget></my-widget>')(scope);

// data binding — Angular encodes the result
$scope.userName = user.name;   // template uses {{ userName }}

// trusted, sanitized content
$scope.body = $sce.trustAsHtml(DOMPurify.sanitize(md));
```

For each finding, point to the sink line and the origin of the untrusted
string. In `poc`, give a concrete AngularJS expression payload (e.g. a
`{{ }}` expression in the reflected/compiled value) and, in `details`,
state explicitly that HTML-encoding does not neutralize it.
</content>
