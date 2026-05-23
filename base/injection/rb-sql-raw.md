---
slug: rb-sql-raw
name: Raw SQL Injection (Ruby)
description: Ruby SQL execution (ActiveRecord find_by_sql / where with string fragments, Sequel.lit, pg gem) with #{} interpolation in the SQL string. Walker mode traces scopes and concerns across files.
version: 0.1.0
author: agentgg
mode: walker
tech: [ruby]
noiseTier: normal
outputType: finding
filePatterns:
  - "**/*.rb"
excludePatterns:
  - "**/spec/**"
  - "**/test/**"
  - "**/*_spec.rb"
  - "**/*_test.rb"
preFilter:
  - regex: "\\.find_by_sql\\s*\\(\\s*[\"'][^\"']*#\\{"
    label: "find_by_sql with #{} interpolation"
  - regex: "\\.where\\s*\\(\\s*[\"'][^\"']*#\\{"
    label: ".where with string-fragment interpolation"
  - regex: "\\.connection\\.execute\\s*\\(\\s*[\"'][^\"']*#\\{"
    label: "connection.execute with interpolation"
  - regex: "Sequel\\.lit\\s*\\(\\s*[\"'][^\"']*#\\{"
    label: "Sequel.lit with interpolation"
  - regex: "\\.exec\\s*\\(\\s*[\"'][^\"']*#\\{"
    label: "pg exec with interpolation"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-89
  - OWASP-A03:2021
---

You are reviewing Ruby source code for SQL injection across
ActiveRecord raw escape hatches, Sequel literal SQL fragments, and
the pg gem. The unsafe pattern is Ruby string interpolation `#{...}`
inside a SQL string passed to a query/execute method — the
interpolation runs before the SQL is sent to the driver, bypassing
parameterization.

**Walker mode advantage:** Rails apps often hide raw SQL in model
scopes (`scope :search, ->(q) { where("name = '#{q}'") }`) or in
shared concerns. The controller looks innocuous (`User.search(q)`)
— follow the import/include chain to the scope definition and check
how the SQL is built there.

## What to look for

**ActiveRecord raw queries with `#{}`:**
```ruby
User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
User.where("name = '#{name}'")
User.where("id = #{user_id}")
User.connection.execute("DELETE FROM users WHERE id = #{id}")
ActiveRecord::Base.connection.execute("UPDATE users SET role = '#{role}'")
```
Safe form: `User.where("name = ?", name)` or `User.where(name: name)`.

**Sequel:**
```ruby
DB[:users].where("name = '#{q}'")
DB.fetch("SELECT * FROM t WHERE col = '#{val}'")
Sequel.lit("name = '#{user_input}'")
```
Safe form: `DB[:users].where(name: q)` or `Sequel.lit("name = ?", q)`.

**pg gem direct execution:**
```ruby
conn.exec("SELECT * FROM users WHERE id = #{user_id}")
```
Safe form: `conn.exec_params("SELECT * FROM users WHERE id = $1", [user_id])`.

## True positive criteria

Flag when ALL of the following hold:

1. A SQL-executing call is made: `find_by_sql`, `where` (with string
   fragment), `connection.execute`, `Sequel.lit`, `DB.fetch`,
   `conn.exec`, `Repository.connection.execute`.
2. The SQL string contains Ruby `#{...}` interpolation.
3. The interpolated value comes from user input (`params`,
   `request.body`, `cookies`, Rails strong-parameters output).

## What to ignore

- `User.where(name: name)` — hash form (parameterized automatically).
- `User.where("name = ?", name)` — placeholder form (parameterized).
- `User.where("name = :name", name: name)` — named placeholder form.
- Hardcoded SQL with no interpolation.
- Test and spec files.

## Examples

True positives:
```ruby
# find_by_sql with interpolation
name = params[:name]
User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")

# where string with interpolation
User.where("id = #{params[:id]}")

# Sequel.lit with interpolation
DB[:users].where(Sequel.lit("name = '#{params[:name]}'"))

# pg gem exec
conn.exec("SELECT * FROM users WHERE id = #{params[:id]}")
```

False positives to skip:
```ruby
# Hash form — safe
User.where(name: params[:name])

# Placeholder form — safe
User.where("name = ?", params[:name])

# Sequel parameterized
Sequel.lit("name = ?", params[:name])

# pg with $1
conn.exec_params("SELECT * FROM users WHERE id = $1", [params[:id]])
```
