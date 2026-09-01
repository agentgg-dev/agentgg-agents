---
slug: database-dump-committed
name: Database Dump or System Credential File Committed
description: 'SQL database dumps (MySQL, PostgreSQL, SQLite), /etc/passwd or /etc/shadow formatted files, KeePass exports (CSV or XML), or cracked-password tool output (John the Ripper, Metasploit) committed to the repository.'
version: 0.1.0
author: agentgg
noiseTier: normal
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: '-- MySQL dump|-- PostgreSQL database dump|SQLite format 3'
      label: Database dump file header (MySQL/PostgreSQL/SQLite)
    - regex: 'DROP\s+(?:TABLE|DATABASE)\s+IF\s+EXISTS\s+\S+\s*;'
      label: SQL dump marker (DROP TABLE/DATABASE IF EXISTS)
    - regex: 'INSERT\s+INTO\s+\S+\s*(?:\([^)]+\))?\s*VALUES\s*\('
      label: SQL data rows (INSERT INTO ... VALUES)
    - regex: '[a-zA-Z0-9_\-]+:[x\*]:\d+:\d+:[^:]*:[^:]*:[^\s]+'
      label: /etc/passwd format line (username:x:uid:gid:...)
    - regex: '[a-zA-Z0-9_\-]+:\$[0-9a-z]+\$[A-Za-z0-9./]{8,}\$[A-Za-z0-9./]{22,}'
      label: /etc/shadow password hash (username:$alg$salt$hash)
    - regex: '"Account","Login Name","Password","Web Site","Comments"'
      label: KeePass 1.x CSV export header (plaintext passwords)
    - regex: '<pwlist>\s*?<pwentry>'
      label: KeePass 1.x XML export (plaintext passwords)
    - regex: 'require\s+[''"]msf/core[''"]|class\s+Metasploit|include\s+Msf::Exploit'
      label: Metasploit exploitation framework module
    - regex: 'Loaded \d+ password hash|guesses:\s*\d+\s+time:|john\.pot'
      label: John the Ripper cracked password output
    - regex: 'Nmap\s+scan\s+report\s+for\s+[a-zA-Z0-9.]+'
      label: Nmap network scan output
references:
  - CWE-312
  - CWE-359
  - CWE-530
  - 'OWASP-A02:2021'
---

You are reviewing repositories for accidentally committed database dumps, system credential files, password manager exports, or security tool output. These are among the most severe accidental exposures.

## Categories and severity

### SQL database dumps

**How to confirm it's a dump (not a migration):**
- Migrations have `CREATE TABLE` / `ALTER TABLE` but usually NO `INSERT INTO` data rows
- Dumps have many `INSERT INTO` statements with real data rows
- Check for a `mysqldump` or `pg_dump` header comment at the top

**What makes it critical:**
- User tables with password hashes (columns: `password`, `password_hash`, `hashed_password`, `pwd`)
- PII columns: `email`, `ssn`, `phone`, `card_number`, `address`, `dob`
- Count the INSERT statements — even a rough count tells you the scale of exposure

### /etc/passwd

Format: `username:x:uid:gid:comment:home_dir:shell`

Reveals system users, home directories, and default shells. Lower immediate risk (password field is just `x`), but confirms system layout. Still should not be in app repos.

### /etc/shadow

Format: `username:$algorithm$salt$hash:...`

**Critical.** Password hashes that can be cracked offline with John the Ripper or hashcat. Weak passwords can be recovered quickly; the hashes should be treated as partially-compromised credentials.

### KeePass exports

**KeePass CSV (`"Account","Login Name","Password","Web Site","Comments"`):** plaintext passwords for all stored accounts — **critical finding.**

**KeePass XML (`<pwlist><pwentry>`):** also exports passwords in plaintext — **critical finding.**

### Security tool output

**Metasploit module:** exploitation framework code in an app repo — should not be there. Investigate why.

**John the Ripper output (`john.pot`, `Loaded N password hashes`):** cracked password output committed — **critical** if the passwords are from production systems.

**Nmap scan output:** network topology data committed — reveals internal infrastructure.

## True positive criteria

Flag at critical:
1. SQL dump with user/payment tables and data rows (`INSERT INTO users VALUES (...)`)
2. /etc/shadow file with password hashes
3. KeePass CSV or XML export in plaintext
4. John the Ripper `.pot` file with cracked passwords

Flag at high:
5. /etc/passwd file committed
6. SQL dump with CREATE TABLE + INSERT but unclear table names
7. Nmap output with internal IP ranges

Flag at lower severity:
8. SQL seed file with obviously synthetic data (4-5 rows, fake names)

## What to ignore

- SQL migration files with only schema changes (no INSERT data rows)
- Test fixture SQL with clearly synthetic data and 4-5 rows

Report: the file type (dump/shadow/KeePass/etc.), what tables or accounts are present, whether password hashes or PII columns are visible, and an estimate of the scale (row count, number of entries).
