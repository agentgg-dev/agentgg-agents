---
slug: jvm-search-acl-filter-skip
name: Skipped ACL Filter Injection in Search Proxy (JVM)
description: 'Java/Kotlin search proxies that forward user-supplied query payloads to Elasticsearch/OpenSearch/Solr after injecting mandatory access-control/permission/visibility filters — where the injection is gated on request shape (e.g. presence of a "query" node) and is skipped when that shape is absent, so a crafted payload reaches the backend unfiltered. Fail-open authorization (CWE-862). Traces the proxy/controller and the filter-building helper to confirm the clause is security-relevant and unconditionally applied.'
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: '(RestHighLevelClient|ElasticsearchClient|OpenSearchClient|RestClient)\b'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Elasticsearch / OpenSearch client
      - regex: '(SearchSourceBuilder|SearchRequest|QueryBuilders\.|BoolQueryBuilder|boolQuery\s*\()'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Elasticsearch query DSL builder
      - regex: '(SolrClient|SolrQuery|CloudSolrClient)\b'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Solr client / query
      - regex: '["'']/?_search\b'
        in:
          - '**/*.{java,kt}'
        notIn:
          - '**/src/test/**'
          - '**/test/**'
          - '**/target/**'
          - '**/build/**'
        label: Elasticsearch/OpenSearch _search endpoint string
  prompt: |
    Run only if this project has a server-side SEARCH PROXY: code that
    forwards user-supplied search/query payloads to a search engine
    (Elasticsearch, OpenSearch, or Solr) AND is responsible for injecting
    its own access-control, permission, visibility, ownership, or tenant
    filters into those queries before they reach the engine.

    Skip if: search results are not access-controlled (fully public
    index), the engine enforces document-level security itself with no
    proxy-side filter, or the project only uses the search engine for
    logging/metrics/internal telemetry with no per-user visibility rules.
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
    - regex: '\.(get|has|remove|put|set|path|findValue)\s*\(\s*["'']query["'']'
      label: JSON "query" node accessed on a parsed request body
    - regex: '(?i)(permission|visibilit|owner|group|access|published|draft|portal|tenant)\w*(filter|clause)'
      label: Permission/visibility filter identifier
    - regex: '(?i)(build|add|inject|apply|append|insert|prepend|wrap)\w*filter\b'
      label: Filter-injection method
    - regex: '["'']/?_search\b'
      label: Elasticsearch/OpenSearch _search endpoint string
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-862
  - CWE-863
  - 'OWASP-A01:2021'
---

You are reviewing a Java/Kotlin **search proxy** — code that forwards a
user-supplied search payload to a search engine (Elasticsearch,
OpenSearch, Solr) after the server injects its own access-control
filters (group/role visibility, ownership, draft/published state,
portal/tenant scoping).

The bug you are hunting is a **fail-open conditional security
transform**: the filter-injection step is mandatory for authorization,
but it is guarded by a condition on the *shape* of the incoming request.
Craft a request that takes the other branch — most commonly by omitting
the top-level `query` node — and the filter is never added, so the
payload reaches the engine with no access restrictions. An
unauthenticated or under-privileged caller then reads records they
should not see. This is CWE-862 (Missing Authorization).

This is NOT "missing auth on an endpoint" (the endpoint is public by
design) and NOT IDOR (there is no resource id). The security control IS
the injected filter, and the defect is that a branch of the request
handler skips it.

## Root-cause shape

```java
JsonNode query = requestBody.get("query");
if (query != null) {                       // <-- gate on request shape
    ObjectNode filtered = addPermissionsFilter(query, userGroups);
    ((ObjectNode) requestBody).set("query", filtered);
}
forwardToElasticsearch(requestBody);       // no-"query" path forwarded UNFILTERED
```

The tell: an `if (hasX) { injectSecurityFilter() }` with **no `else`**,
where "no X" means "no filter" instead of "deny" or "filter an empty /
match-all query". The same defect appears as:

- injecting the filter only when a `filter`/`bool` block already exists,
- rewriting only one payload variant (POST body but not a GET
  `source=` param, or one content-type but not another),
- skipping injection when the body is empty / missing / fails to parse,
- an early `return`/`continue` on an unexpected shape that jumps over
  the filter step.

## Cross-file analysis

- Open the filter-building helper (`addPermissionsFilter`,
  `buildAccessFilter`, `getPermissionsFilter`, etc.). Confirm the clause
  it builds is genuinely **security-relevant** — it references groups,
  roles, owner/ownership, `isPublished`/draft, visibility, or tenant.
  If the conditional block only adds sorting, a relevance boost,
  highlighting, or pagination, it is NOT a security control — ignore.
- Trace how the request reaches the engine (the forward/execute call).
  Confirm the no-filter branch actually gets forwarded, rather than
  rejected with a 400 or short-circuited.
- Check whether the engine enforces its own document-level security. If
  the proxy filter is pure defense-in-depth and the backend independently
  restricts results, downgrade or skip.

## True positive criteria

Flag when ALL of the following hold:

1. The file forwards a user-influenced search/query payload to
   Elasticsearch/OpenSearch/Solr.
2. An access-control / permission / visibility / ownership / tenant
   filter is injected into that payload by the proxy.
3. The injection is guarded by a condition on request shape (presence of
   a `query` node, a specific block, a method/content-type, non-empty
   body, successful parse), and there is a reachable branch where the
   payload is still forwarded but the filter is NOT applied.

## What to ignore

- Injection that runs unconditionally, e.g. a missing `query` is first
  synthesized to `match_all` and THEN wrapped with the filter, so every
  path is filtered.
- Conditional blocks that add non-security concerns (sort, boost,
  highlight, aggregations, pagination).
- Proxies over a fully public index where results are not
  access-controlled at all.
- Backends that enforce document-level security independently of the
  proxy filter.
- Tests, fixtures.

## Examples

True positives:
```java
// GeoNetwork-style: filter added only when the body carries a "query"
if (requestBody.has("query")) {
    JsonNode filtered = buildPermissionsFilter(requestBody.get("query"), session);
    ((ObjectNode) requestBody).set("query", filtered);
}
esProxy.execute("/_search", requestBody);   // omit "query" -> unfiltered read
```
```java
// Filter only applied to the bool.filter path; a bare match_all skips it
ObjectNode q = (ObjectNode) body.path("query");
if (q.has("bool")) {
    addGroupVisibilityFilter(q.get("bool"), userGroups);
}
client.search(body);                        // {"query":{"match_all":{}}} bypasses
```

False positives to skip:
```java
// Missing query is synthesized first, THEN filtered — every path is scoped
if (!body.has("query")) {
    ((ObjectNode) body).set("query", matchAll());
}
((ObjectNode) body).set("query",
    wrapWithPermissionsFilter(body.get("query"), session));  // unconditional
client.search(body);

// Conditional block is not a security control
if (body.has("query")) {
    applyRelevanceBoost(body.get("query"));   // boost, not access control
}
```

For each candidate, point to the exact `if`/branch that gates the filter
injection and the forward call that runs without it. In `details`,
name the security clause that gets skipped (which permission/visibility
dimension) and, in `poc`, give the concrete request shape (e.g. a
`_search` body with no `query` field) that reaches the engine unfiltered.
</content>
</invoke>
