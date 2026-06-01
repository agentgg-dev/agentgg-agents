---
slug: missing-auth-php
name: Missing Authentication on PHP Endpoint
description: 'PHP route handlers (Laravel routes/controllers, Symfony controllers, Slim/raw PHP route files, WordPress REST routes) with no authentication check — every endpoint reachable without a session is public. Walker mode follows route-group middleware, controller-level attributes, and shared base controllers across files.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'Route::(get|post|put|patch|delete|any|match|resource)\s*\('
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: 'Laravel Route::* registration'
      - regex: \$(app|router|slim)->(get|post|put|patch|delete|any|map)\s*\(
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: Slim / micro-framework route registration
      - regex: '#\[\s*Route\s*\('
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: 'Symfony PHP8 #[Route] attribute'
      - regex: '@Route\s*\('
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: Symfony annotation @Route
      - regex: class\s+\w+Controller\s+extends\s+\w*Controller\b
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: Controller subclass
      - regex: register_rest_route\s*\(
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: WordPress register_rest_route()
      - regex: 'public\s+function\s+\w+\s*\([^)]*Request\b'
        in:
          - '**/routes/**/*.php'
          - '**/app/Http/Controllers/**/*.php'
          - '**/src/Controller/**/*.php'
          - '**/src/Controllers/**/*.php'
          - '**/Controllers/**/*.php'
          - '**/public/index.php'
        notIn:
          - '**/tests/**'
          - '**/test/**'
          - '**/Tests/**'
          - '**/vendor/**'
          - '**/node_modules/**'
          - '**/storage/**'
          - '**/bootstrap/cache/**'
        label: Public action method receiving Request
  prompt: 'Run only if this project uses php, laravel, symfony, slim, yii, cakephp, codeigniter, wordpress, drupal — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.'
where:
  filePatterns:
    - '**/routes/**/*.php'
    - '**/app/Http/Controllers/**/*.php'
    - '**/src/Controller/**/*.php'
    - '**/src/Controllers/**/*.php'
    - '**/Controllers/**/*.php'
    - '**/public/index.php'
  excludePatterns:
    - '**/tests/**'
    - '**/test/**'
    - '**/Tests/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/storage/**'
    - '**/bootstrap/cache/**'
  preFilter:
    - regex: 'Route::(get|post|put|patch|delete|any|match|resource)\s*\('
      label: 'Laravel Route::* registration'
    - regex: \$(app|router|slim)->(get|post|put|patch|delete|any|map)\s*\(
      label: Slim / micro-framework route registration
    - regex: '#\[\s*Route\s*\('
      label: 'Symfony PHP8 #[Route] attribute'
    - regex: '@Route\s*\('
      label: Symfony annotation @Route
    - regex: class\s+\w+Controller\s+extends\s+\w*Controller\b
      label: Controller subclass
    - regex: register_rest_route\s*\(
      label: WordPress register_rest_route()
    - regex: 'public\s+function\s+\w+\s*\([^)]*Request\b'
      label: Public action method receiving Request
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-306
  - 'OWASP-A01:2021'
---

You are reviewing PHP HTTP route handlers for missing authentication —
endpoints that handle requests but never call an auth check, so every
caller is treated as authorized regardless of session.

**Walker mode advantage:** an unguarded-looking controller action may
be covered by route-group middleware (Laravel `Route::group(['middleware'
=> 'auth'], ...)`), a controller-level `__construct` calling
`$this->middleware('auth')`, a Symfony attribute on the controller
class, or a base controller it extends. Open those before reporting:

- For Laravel: check `routes/web.php` / `routes/api.php` /
  `routes/*.php` for a `Route::group(['middleware' => ...])` or
  `->middleware(...)` chained on the route. Check the controller's
  `__construct` for `$this->middleware('auth')`. Check
  `app/Http/Kernel.php` for global middleware that covers the route's
  group.
- For Symfony: check class-level `#[IsGranted(...)]` or
  `#[Route(..., name: ..., methods: ...)]` paired with a `firewalls`
  pattern in `config/packages/security.yaml`.
- For WordPress: check the `permission_callback` argument on
  `register_rest_route`.

## What to look for

**Laravel controller action with no auth:**
```php
class UsersController extends Controller {
    public function index(Request $request) {
        return User::all();
    }
}
```
If neither the route registration nor the controller's `__construct`
binds auth middleware, this is public.

**Slim / raw PHP route:**
```php
$app->get('/users', function ($req, $res) {
    return $res->withJson(User::all());
});
```

**Symfony controller without #[IsGranted]:**
```php
#[Route('/users', methods: ['GET'])]
public function index(): JsonResponse { ... }
```
Symfony falls back to `security.yaml` firewalls — confirm the path is
covered there before reporting.

**WordPress REST route without permission_callback:**
```php
register_rest_route('myplugin/v1', '/users', [
    'methods'  => 'GET',
    'callback' => 'my_handler',
    // no permission_callback → __return_true by default → public
]);
```

**Auth indicators that, if PRESENT, mean the endpoint is protected:**

- Laravel: `->middleware('auth')`, `->middleware('auth:sanctum')`,
  `->middleware('auth:api')`, `Route::group(['middleware' => 'auth'],
  ...)`, `$this->middleware('auth')` in `__construct`,
  `Gate::authorize(...)`, `$this->authorize(...)`,
  `Auth::check()`/`auth()->check()` early-return guards.
- Symfony: `#[IsGranted(...)]`, `$this->denyAccessUnlessGranted(...)`,
  a `firewalls:` rule in `security.yaml` matching the route's path.
- Slim: a middleware passed to `$app->add(...)` or
  `->add($authMiddleware)` chained on the route.
- WordPress: `'permission_callback' => 'is_user_logged_in'` or a
  custom callable that does a capability check.

## True positive criteria

Flag when ALL of the following hold:

1. The file contains an HTTP handler (Laravel controller action with
   a `Request`-bound public method, Slim/raw `$app->VERB`, Symfony
   `#[Route]` method, WordPress `register_rest_route` callback).
2. No auth indicator (above) appears in the file, the route
   registration that points at the handler, OR a route group that
   wraps it.
3. The endpoint is not a public-by-design surface (login, register,
   forgot-password, health, webhook with HMAC verification, OpenAPI
   docs).

## What to ignore

- Genuinely public endpoints: `/login`, `/register`, `/forgot-password`,
  `/health`, `/version`, `/oauth/callback`, webhooks that verify their
  own signature (flag those under `webhook-handler` instead).
- Login/auth controllers themselves (`LoginController`, `AuthController`
  actions that ISSUE auth).
- Static asset / file-serving handlers.
- Handlers wrapped at the route-group level — open the route file and
  confirm before flagging.
- Test files, fixtures, factories.

## Examples

True positives:
```php
// Laravel — controller action, no auth anywhere
class TransferController extends Controller {
    public function store(Request $request) {
        return Transfer::create($request->all()); // public + mass-assignment
    }
}
// routes/api.php — no middleware
Route::post('/transfer', [TransferController::class, 'store']);

// WordPress — no permission_callback → public
register_rest_route('api/v1', '/users', [
    'methods'  => WP_REST_Server::READABLE,
    'callback' => 'list_users',
]);

// Symfony — no #[IsGranted], no firewalls coverage in security.yaml
#[Route('/admin/users', methods: ['DELETE'])]
public function delete(int $id): JsonResponse { ... }
```

False positives to skip:
```php
// Auth middleware on the route group
Route::middleware('auth')->group(function () {
    Route::get('/users', [UsersController::class, 'index']);
});

// Controller-level middleware
class UsersController extends Controller {
    public function __construct() {
        $this->middleware('auth');
    }
    public function index() { return User::all(); }
}

// Symfony — explicit auth attribute
#[Route('/admin', methods: ['GET'])]
#[IsGranted('ROLE_ADMIN')]
public function admin(): Response { ... }

// WordPress — permission_callback present
register_rest_route('api/v1', '/me', [
    'methods'             => 'GET',
    'callback'            => 'get_me',
    'permission_callback' => 'is_user_logged_in',
]);
```
