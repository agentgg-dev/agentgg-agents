---
slug: py-airflow-dag
name: Airflow DAG Entry Points
description: Locates Airflow DAGs, operators, and Jinja templating — sensitive prod surface — via regex — no LLM cost.
version: 0.1.0
author: agentgg
mode: rule
tech: [airflow]
noiseTier: noisy
filePatterns:
  - "**/dags/**/*.py"
  - "**/*.py"
excludePatterns:
  - "**/tests/**"
  - "**/test/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
preFilter:
  - regex: "\\bDAG\\s*\\(\\s*['\"]"
    label: "DAG('id', ...) declaration"
  - regex: "\\b@dag\\b\\s*\\("
    label: "@dag decorator (TaskFlow API)"
  - regex: "\\b(?:Bash|Python|Docker|Postgres|S3|HTTP)Operator\\s*\\("
    label: "Operator instantiation (review templated args)"
  - regex: "\\{\\{\\s*[^}]+\\s*\\}\\}"
    label: "Jinja template — review for injection"
  - regex: "\\bbash_command\\s*=\\s*f?['\"][^'\"]*\\{"
    label: "bash_command with templating"
references:
  - CWE-78
  - CWE-89
  - CWE-862
---

Regex-only rule (no LLM). Locates Airflow DAGs, operators, and
Jinja-templated arguments — a sensitive prod surface where
templating becomes a command/SQL injection vector.

Gated on `tech: [airflow]` — only runs when `fingerprint(root)`
detects Airflow.

## What this finds

- `DAG('id', ...)` declarations
- `@dag(...)` decorators (TaskFlow API)
- `BashOperator` / `PythonOperator` / `DockerOperator` /
  `PostgresOperator` / `S3Operator` / `HTTPOperator` instantiations
- `{{ jinja }}` template expressions
- `bash_command = f"... {var} ..."` templated commands

## What this does NOT do

This rule does not classify findings — only locates candidates.
Downstream walker agents decide whether they represent a real
vulnerability.
