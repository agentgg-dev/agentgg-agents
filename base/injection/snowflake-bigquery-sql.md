---
slug: snowflake-bigquery-sql
name: Analytics SQL Injection (Snowflake / BigQuery / ClickHouse / DuckDB)
description: Snowflake / BigQuery / ClickHouse / DuckDB queries built with template literal interpolation or string concatenation — analytics endpoints are real query engines and these patterns are SQL injection. Walker mode confirms the warehouse SDK is in use and follows query helpers.
version: 0.1.0
author: agentgg
noiseTier: precise
precondition:
  regex:
    patterns:
      - regex: 'execute\s*\(\s*\{\s*sqlText\s*:\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: Snowflake execute sqlText with template-literal interpolation
      - regex: 'bigquery\.(query|createQueryJob)\s*\([^)]*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: BigQuery query/createQueryJob with template-literal interpolation
      - regex: 'clickhouse\.query\s*\(\s*`[^`]*\$\{|client\.query\s*\(\s*\{\s*query\s*:\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: ClickHouse query with template-literal interpolation
      - regex: '\bduckdb\b[\s\S]{0,200}\.execute\s*\(\s*`[^`]*\$\{'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: DuckDB execute with template-literal interpolation
      - regex: 'from\s+[''"](snowflake-sdk|@google-cloud/bigquery|@clickhouse/client|@databricks/sql|duckdb|@duckdb/)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
          - '**/.next/**'
        label: imports analytics warehouse SDK (confirms context)
where:
  extensions:
    - ts
    - tsx
    - js
    - jsx
    - mjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: 'execute\s*\(\s*\{\s*sqlText\s*:\s*`[^`]*\$\{'
      label: Snowflake execute sqlText with template-literal interpolation
    - regex: 'bigquery\.(query|createQueryJob)\s*\([^)]*`[^`]*\$\{'
      label: BigQuery query/createQueryJob with template-literal interpolation
    - regex: 'clickhouse\.query\s*\(\s*`[^`]*\$\{|client\.query\s*\(\s*\{\s*query\s*:\s*`[^`]*\$\{'
      label: ClickHouse query with template-literal interpolation
    - regex: '\bduckdb\b[\s\S]{0,200}\.execute\s*\(\s*`[^`]*\$\{'
      label: DuckDB execute with template-literal interpolation
    - regex: 'from\s+[''"](snowflake-sdk|@google-cloud/bigquery|@clickhouse/client|@databricks/sql|duckdb|@duckdb/)'
      label: imports analytics warehouse SDK (confirms context)
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing TypeScript / JavaScript source code for SQL
injection against analytics warehouses — Snowflake, BigQuery,
ClickHouse, DuckDB, Databricks. These look like "analytics" code, but
the destination is a real query engine; template-literal
interpolation is exploitable the same way as on Postgres.

**Walker mode advantage:** analytics SDKs often have project-specific
wrappers (`lib/warehouse.ts`, `analytics/query.ts`) where the
unsafe pattern hides. Follow imports to verify whether the wrapper
parameterizes (`binds`, `params`, `query_params`) or just forwards
the raw string. Confirm the warehouse SDK is imported — a generic
`db.query()` call is not in scope for this agent.

## What to look for

**Snowflake SDK (`snowflake-sdk`):**
```ts
import snowflake from "snowflake-sdk";
connection.execute({ sqlText: `SELECT * FROM users WHERE id = ${id}` });
connection.execute({ sqlText: "SELECT * FROM users WHERE id = " + id });
```
Safe form: `connection.execute({ sqlText: "SELECT ... WHERE id = ?", binds: [id] })`.

**BigQuery (`@google-cloud/bigquery`):**
```ts
import { BigQuery } from "@google-cloud/bigquery";
await bigquery.query(`SELECT * FROM users WHERE id = ${id}`);
await bigquery.createQueryJob({ query: `SELECT * FROM ${tableName}` });
```
Safe form: `bigquery.query({ query: "SELECT ... WHERE id = @id", params: { id } })`.

**ClickHouse (`@clickhouse/client` / `@clickhouse/client-web`):**
```ts
await clickhouse.query(`SELECT * FROM users WHERE id = ${id}`);
await client.query({ query: `SELECT * FROM ${table}` });
```
Safe form: `clickhouse.query({ query: "SELECT ... WHERE id = {id:Int32}", query_params: { id } })`.

**DuckDB (`duckdb` / `@duckdb/*`):**
```ts
import duckdb from "duckdb";
await connection.execute(`SELECT * FROM ${table}`);
```
Safe form: prepared statement via `db.prepare(...)`.

**Databricks (`@databricks/sql`):**
Same template-literal interpolation patterns apply.

## True positive criteria

Flag when ALL of the following hold:

1. The file imports from `snowflake-sdk`, `@google-cloud/bigquery`,
   `@clickhouse/client*`, `@databricks/sql`, `duckdb`, or `@duckdb/*`.
2. A query is executed via `execute({ sqlText: ... })`,
   `query(...)`, or `createQueryJob({ query: ... })`.
3. The query string contains template literal interpolation (`${...}`)
   or `+` concatenation with a non-constant value.
4. The interpolated value comes from user input.

## What to ignore

- Snowflake `binds: [...]` form with `?` placeholders.
- BigQuery `params: {...}` with `@param` placeholders.
- ClickHouse `query_params: {...}` with `{name:Type}` placeholders.
- DuckDB prepared statements.
- Fully hardcoded SQL.
- Test files.

## Examples

True positives:
```ts
// Snowflake — sqlText with template literal
import snowflake from "snowflake-sdk";
connection.execute({
  sqlText: `SELECT * FROM events WHERE user_id = ${req.body.userId}`,
});

// BigQuery — query with template literal
import { BigQuery } from "@google-cloud/bigquery";
await bigquery.query(`SELECT * FROM logs WHERE event = '${event}'`);

// ClickHouse — query with concat
await clickhouse.query("SELECT count() FROM events WHERE user_id = " + userId);

// DuckDB
await connection.execute(`SELECT * FROM ${req.query.table}`);
```

False positives to skip:
```ts
// Snowflake — binds
connection.execute({
  sqlText: "SELECT * FROM events WHERE user_id = ?",
  binds: [userId],
});

// BigQuery — params
await bigquery.query({
  query: "SELECT * FROM logs WHERE event = @event",
  params: { event },
});

// ClickHouse — query_params
await clickhouse.query({
  query: "SELECT count() FROM events WHERE user_id = {user_id:UInt64}",
  query_params: { user_id: userId },
});
```
