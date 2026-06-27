---
slug: missing-input-bounds
name: Missing Input Bounds Before Resource-Intensive Operations
description: 'User-supplied size, count, depth, or structured data (arrays, polygons, trees) flows into memory allocation, loops, or computationally expensive algorithms without prior bounds or structural validation, enabling DoS via OOM or CPU exhaustion.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: 'boost::geometry|#include\s*[<"]boost/geometry|CGAL::|shapely\.|turf\.'
        in:
          - '**/*.{cc,cpp,h,hpp,py,js,ts}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.*'
          - '**/node_modules/**'
          - '**/dist/**'
        label: geometric library
      - regex: '(malloc|calloc|new\s+\w+\[|make\s*\(\[\])[^;]{0,60}(size|count|len|n|num|limit)\b'
        in:
          - '**/*.{cc,cpp,h,hpp,go,java,cs,rs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.*'
          - '**/node_modules/**'
          - '**/dist/**'
        label: allocation with size variable
      - regex: 'np\.(zeros|ones|empty|full|array|reshape)\s*\('
        in:
          - '**/*.py'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.*'
          - '**/node_modules/**'
        label: numpy allocation
where:
  extensions:
    - cc
    - cpp
    - h
    - hpp
    - py
    - go
    - java
    - cs
    - rs
    - js
    - ts
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.*'
    - '**/*.spec.*'
    - '**/node_modules/**'
    - '**/dist/**'
  preFilter:
    - regex: 'boost::geometry|CGAL::|shapely\.|turf\.|#include\s*[<"]boost/geometry'
      label: geometric library usage
    - regex: '(malloc|calloc)\s*\([^)]{0,60}(size|count|len|n|num)\b'
      label: C malloc/calloc with size variable
    - regex: '(malloc|calloc|new\s+\w+\[|make\s*\(\[\]\w+,)\s*[^;]{0,60}(size|count|len|n|num|limit)\b'
      label: C/Go allocation with size variable
    - regex: 'np\.(zeros|ones|empty|full|reshape)\s*\([^)]{0,80}(n|size|count|shape|dim)\b'
      label: numpy allocation with size variable
    - regex: 'exclude_polygon|polygon_ring|convex_hull|triangulat|voronoi'
      label: polygon or geometric algorithm
    - regex: 'make\s*\(\[\]\w+,\s*[a-z][a-zA-Z0-9_]*\)'
      label: Go slice allocation with size variable
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-400
  - CWE-770
  - CWE-20
---

You are reviewing code for missing input validation before
resource-intensive operations. The anti-pattern: a user-supplied value
(size, count, depth, or structured data like a polygon or tree) flows
into an expensive operation — memory allocation, a loop, a geometric
algorithm — without a prior bounds or structural validity check. A
malicious or malformed request can trigger OOM, CPU exhaustion, or
pathological algorithm behavior.

**Cross-file analysis:** the value being validated (or not) often
originates in a request handler, is parsed into an options or config
struct, and is passed down to a processing function several calls deep.
Open the call chain to find where the value enters and where the
expensive operation occurs — the missing check should sit between them.

## What to look for

**Unbounded memory allocation from user input**
```cpp
// User supplies "count" in request body
size_t count = options.count(); // from JSON body
std::vector<Result> results;
results.resize(count);  // VULNERABLE: count unchecked, could be 2^32
```
```go
n := r.FormValue("limit")
size, _ := strconv.Atoi(n)
buf := make([]byte, size)  // VULNERABLE: no upper bound check
```
```python
n = int(request.args.get('size', 100))
data = np.zeros((n, n))  # VULNERABLE: n=50000 → 20 GB allocation
```

**Degenerate or adversarial structured input**
```cpp
// User supplies exclude_polygons in request body
for (const auto& ring : options.exclude_polygons()) {
    // boost::geometry::area() on a zero-area (collinear) ring
    // causes unbounded memory growth inside the algorithm
    auto area = boost::geometry::area(ring);  // VULNERABLE
}
// Fix: validate ring.size() >= 3 and area > epsilon before processing
```
```python
polygon = request.json['polygon']  # user-supplied list of [lat, lon] pairs
shape = shapely.geometry.Polygon(polygon)
# VULNERABLE: degenerate polygon (collinear, self-intersecting) causes
# shapely to enter pathological computation paths
result = shape.buffer(0)
```

**Unbounded recursion depth from user input**
```js
function parseNode(data, depth) {
  // VULNERABLE: no depth limit, deeply nested JSON causes stack overflow
  return data.children.map(c => parseNode(c, depth + 1));
}
const tree = parseNode(req.body.tree, 0);
```

**Loop count from user input**
```java
int iterations = Integer.parseInt(request.getParameter("rounds"));
// VULNERABLE: no upper bound on iterations
for (int i = 0; i < iterations; i++) {
    expensiveWork();
}
```

## True positive criteria

Flag when ALL of the following hold:

1. A value originates from user-controlled input: query params,
   request body fields, JSON properties, or any data that crosses a
   network boundary.
2. That value is used (directly or transitively, within a few call
   levels) to control the amount of work performed: allocation size,
   collection resize, loop iteration count, recursion depth, or as
   input to a computationally expensive algorithm (geometry, image
   processing, compression, cryptographic work).
3. No bounds check or structural validation is applied between the
   point of input and the expensive operation. Adequate validation
   means an explicit upper bound check (`if n > MAX_N`) for numeric
   sizes, or a structural validity check (non-zero area, finite
   coordinates, depth limit) for structured data.

## What to ignore

- Values explicitly clamped or bounded before use:
  `size = Math.min(size, MAX_SIZE)` or `if (count > LIMIT) return err`.
- Allocations whose size is derived from a hardcoded constant or
  configuration value not reachable by the user.
- Expensive algorithms applied to data loaded from the server's own
  filesystem or a trusted internal service, not from the request.
- Libraries or frameworks that already enforce internal limits
  (e.g. body-parser's `limit` option already caps request body size).

## Examples

True positives:
```cpp
// C++ — polygon from request, no area/size check before algorithm
const auto& polys = options.exclude_polygons();
for (const auto& p : polys) {
    // no: if (p.outer().size() < 3 || boost::geometry::area(p) < 1e-9)
    result = algorithm_that_oom_on_degenerate(p);
}

// Go — slice size from request param, no upper bound
n, _ := strconv.Atoi(r.URL.Query().Get("n"))
data := make([]Record, n)

// Python — numpy array shaped by user input
rows = int(request.form['rows'])
cols = int(request.form['cols'])
matrix = np.zeros((rows, cols))  # rows=100000, cols=100000 → crash
```

False positives to skip:
```cpp
// Bounds check present before allocation
size_t count = options.count();
if (count == 0 || count > MAX_POLYGON_POINTS) {
    return error_response("invalid count");
}
results.resize(count);

// Go — clamped before use
n := min(requestedSize, MAX_ALLOWED)
buf := make([]byte, n)
```
