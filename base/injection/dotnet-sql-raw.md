---
slug: dotnet-sql-raw
name: Raw SQL Injection (.NET)
description: '.NET SQL execution (ADO.NET SqlCommand, Dapper, EF Core FromSqlRaw / ExecuteSqlRaw) with string concatenation or C# $"" interpolation — FromSqlInterpolated is safe. Walker mode traces helper methods to verify the SQL source.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: new\s+SqlCommand\s*\(\s*\$"
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: SqlCommand with $"..." interpolation
      - regex: 'new\s+SqlCommand\s*\([^,)]*\+'
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: SqlCommand with string concatenation
      - regex: '\.CommandText\s*=\s*(\$"|[^;]*\+)'
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: CommandText assigned via interpolation/concat
      - regex: '\.(Query|Execute|QueryAsync|ExecuteAsync)(<[^>]+>)?\s*\(\s*\$"'
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: Dapper Query/Execute with $"..." interpolation
      - regex: FromSqlRaw\s*\(\s*\$"
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: EF Core FromSqlRaw with $"..." (use FromSqlInterpolated)
      - regex: ExecuteSqlRaw\s*\(\s*\$"
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: EF Core ExecuteSqlRaw with $"..." (use ExecuteSqlInterpolated)
      - regex: '(FromSqlRaw|ExecuteSqlRaw)\s*\([^,)]*\+'
        in:
          - '**/*.cs'
        notIn:
          - '**/Tests/**'
          - '**/UnitTests/**'
          - '**/IntegrationTests/**'
          - '**/*.Tests/**'
          - '**/bin/**'
          - '**/obj/**'
        label: EF Core SqlRaw with string concatenation
  prompt: Run only if this project uses dotnet — look for it in the manifest (package.json / composer.json / go.mod / etc.) and in the code.
where:
  extensions:
    - cs
  excludePatterns:
    - '**/Tests/**'
    - '**/UnitTests/**'
    - '**/IntegrationTests/**'
    - '**/*.Tests/**'
    - '**/bin/**'
    - '**/obj/**'
  preFilter:
    - regex: new\s+SqlCommand\s*\(\s*\$"
      label: SqlCommand with $"..." interpolation
    - regex: 'new\s+SqlCommand\s*\([^,)]*\+'
      label: SqlCommand with string concatenation
    - regex: '\.CommandText\s*=\s*(\$"|[^;]*\+)'
      label: CommandText assigned via interpolation/concat
    - regex: '\.(Query|Execute|QueryAsync|ExecuteAsync)(<[^>]+>)?\s*\(\s*\$"'
      label: Dapper Query/Execute with $"..." interpolation
    - regex: FromSqlRaw\s*\(\s*\$"
      label: EF Core FromSqlRaw with $"..." (use FromSqlInterpolated)
    - regex: ExecuteSqlRaw\s*\(\s*\$"
      label: EF Core ExecuteSqlRaw with $"..." (use ExecuteSqlInterpolated)
    - regex: '(FromSqlRaw|ExecuteSqlRaw)\s*\([^,)]*\+'
      label: EF Core SqlRaw with string concatenation
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-89
  - 'OWASP-A03:2021'
---

You are reviewing C# / .NET source code for SQL injection across
ADO.NET, Dapper, and Entity Framework Core. The unsafe pattern is the
SQL string being built via `+` concatenation or C# string
interpolation (`$"..."`) before being passed to a SQL execution
method.

**Walker mode advantage:** SQL is often constructed in a repository
class or extension method and passed to the executing call. Follow
the call graph: a `FromSqlRaw(GetUserQuery(id))` is safe if
`GetUserQuery` returns a constant + adds positional parameters,
unsafe if it concatenates `id` into the string. Open the helper.

## Important: FromSqlRaw vs FromSqlInterpolated

- **`FromSqlInterpolated($"SELECT ... WHERE Id = {id}")`** — safe.
  EF Core extracts the interpolated values as bind parameters.
- **`FromSqlRaw($"SELECT ... WHERE Id = {id}")`** — unsafe. EF Core
  treats the resulting string as-is, no parameterization.
- **`FromSqlRaw("SELECT ... WHERE Id = {0}", id)`** — safe. Uses
  positional parameters.

## What to look for

**ADO.NET SqlCommand:**
```csharp
var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);
var cmd = new SqlCommand($"SELECT * FROM users WHERE id = {userId}", conn);
command.CommandText = "DELETE FROM users WHERE id = " + id;
command.CommandText = $"UPDATE users SET role = '{role}'";
```
Safe form: `new SqlCommand("SELECT ... WHERE id = @id", conn)` and
`cmd.Parameters.AddWithValue("@id", userId)`.

**Dapper:**
```csharp
var users = connection.Query<User>($"SELECT * FROM users WHERE name = '{name}'");
connection.Execute("DELETE FROM users WHERE id = " + id);
var rows = connection.QueryAsync<int>($"SELECT id FROM users WHERE id = {id}");
```
Safe form: `connection.Query<User>("SELECT * FROM users WHERE name = @Name", new { Name = name })`.

**Entity Framework Core:**
```csharp
var blogs = ctx.Blogs.FromSqlRaw($"SELECT * FROM Blogs WHERE Id = {id}").ToList();
ctx.Database.ExecuteSqlRaw("DELETE FROM Users WHERE Id = " + id);
```
Safe forms:
- `ctx.Blogs.FromSqlInterpolated($"SELECT * FROM Blogs WHERE Id = {id}")`
- `ctx.Blogs.FromSqlRaw("SELECT * FROM Blogs WHERE Id = {0}", id)`
- `ctx.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Id = {id}")`

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `new SqlCommand`, `command.CommandText =`,
   Dapper `Query`/`Execute`/`QueryAsync`/`ExecuteAsync` (with single
   string argument), `FromSqlRaw`, `ExecuteSqlRaw`.
2. The SQL string is built with `+` concatenation or `$""`
   interpolation that includes a non-constant value.
3. The value comes from user input (ASP.NET request model, query
   string, form data).

## What to ignore

- `FromSqlInterpolated` / `ExecuteSqlInterpolated` — these
  parameterize the `$""` interpolation under the hood.
- `FromSqlRaw("..." + " WHERE x = {0}", value)` — positional
  parameters are safe.
- Parameterized commands using `SqlCommand` with
  `Parameters.AddWithValue` or `Parameters.Add`.
- Dapper with anonymous object parameters: `Query("... WHERE x = @x", new { x })`.
- Hardcoded SQL.
- Tests under `Tests/`, `UnitTests/`, `IntegrationTests/`.

## Examples

True positives:
```csharp
// ADO.NET SqlCommand with $""
var cmd = new SqlCommand($"SELECT * FROM users WHERE name = '{name}'", conn);

// Dapper with $""
var users = connection.Query<User>($"SELECT * FROM users WHERE email = '{email}'");

// EF Core FromSqlRaw with $""
var blog = ctx.Blogs.FromSqlRaw($"SELECT * FROM Blogs WHERE Title = '{title}'").FirstOrDefault();

// ExecuteSqlRaw with concat
ctx.Database.ExecuteSqlRaw("DELETE FROM Users WHERE Id = " + userId);
```

False positives to skip:
```csharp
// FromSqlInterpolated — safe (parameterized)
var blog = ctx.Blogs.FromSqlInterpolated($"SELECT * FROM Blogs WHERE Id = {id}").FirstOrDefault();

// ADO.NET parameterized
var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
cmd.Parameters.AddWithValue("@name", name);

// Dapper parameterized
connection.Query<User>("SELECT * FROM users WHERE id = @Id", new { Id = id });

// FromSqlRaw with positional params
ctx.Blogs.FromSqlRaw("SELECT * FROM Blogs WHERE Id = {0}", id);
```
