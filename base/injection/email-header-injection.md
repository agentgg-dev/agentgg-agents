---
slug: email-header-injection
name: Email Header (CRLF) Injection
description: 'User-controlled input interpolated into email headers (To/Cc/Bcc/From/Subject/Reply-To) without stripping CR/LF — letting an attacker inject extra headers or recipients. Sinks: PHP mail() headers, Python smtplib/email, Node nodemailer. Traces header values back to request input.'
version: 0.1.0
author: agentgg
noiseTier: normal
precondition:
  regex:
    patterns:
      - regex: '\bmail\s*\([^;]*,[^;]*,[^;]*,'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
        label: PHP mail() with additional-headers argument
      - regex: '(From|To|Cc|Bcc|Reply-To|Subject)\s*:.*\$|"(From|To|Cc|Bcc|Reply-To)"\s*:'
        in:
          - '**/*.php'
        notIn:
          - '**/vendor/**'
          - '**/tests/**'
        label: PHP email header line built with a variable
      - regex: 'msg\s*\[\s*[''"](To|From|Cc|Bcc|Reply-To|Subject)[''"]\s*\]\s*=|add_header\s*\(|sendmail\s*\(|smtplib'
        in:
          - '**/*.py'
        notIn:
          - '**/tests/**'
          - '**/test_*.py'
          - '**/*_test.py'
        label: Python email header set / smtplib send
      - regex: '\b(to|cc|bcc|from|replyTo|subject)\s*:\s*(req\.|request\.|params\.|query\.|body\.)'
        in:
          - '**/*.{ts,tsx,js,jsx,mjs,cjs}'
        notIn:
          - '**/__tests__/**'
          - '**/*.test.{ts,tsx,js,jsx,mjs}'
          - '**/*.spec.{ts,tsx,js,jsx,mjs}'
          - '**/node_modules/**'
          - '**/dist/**'
        label: Node nodemailer field from request input
where:
  extensions:
    - php
    - py
    - ts
    - tsx
    - js
    - jsx
    - mjs
    - cjs
  excludePatterns:
    - '**/__tests__/**'
    - '**/*.test.{ts,tsx,js,jsx,mjs}'
    - '**/*.spec.{ts,tsx,js,jsx,mjs}'
    - '**/tests/**'
    - '**/test_*.py'
    - '**/*_test.py'
    - '**/spec/**'
    - '**/vendor/**'
    - '**/node_modules/**'
    - '**/dist/**'
    - '**/.next/**'
  preFilter:
    - regex: '\bmail\s*\([^;]*,[^;]*,[^;]*,'
      label: PHP mail() with additional-headers argument
    - regex: '(From|To|Cc|Bcc|Reply-To|Subject)\s*:.*\$|"(From|To|Cc|Bcc|Reply-To)"\s*:'
      label: PHP email header line built with a variable
    - regex: 'msg\s*\[\s*[''"](To|From|Cc|Bcc|Reply-To|Subject)[''"]\s*\]\s*=|add_header\s*\(|sendmail\s*\(|smtplib'
      label: Python email header set / smtplib send
    - regex: '\b(to|cc|bcc|from|replyTo|subject)\s*:\s*(req\.|request\.|params\.|query\.|body\.)'
      label: Node nodemailer field from request input
  maxFilesPerBatch: 5
  maxTurnsPerBatch: 30
references:
  - CWE-93
  - CWE-94
---

You are reviewing source for email header (CRLF) injection — code that
interpolates user-controlled input into an email header value (To, Cc,
Bcc, From, Subject, Reply-To, or raw additional headers) without
stripping carriage-return / line-feed characters. Because headers are
delimited by `\r\n`, an attacker who embeds CRLF into a header value can
terminate the current header and inject new ones — adding hidden Bcc
recipients (turning your app into a spam relay), spoofing From, or
injecting a body.

**Cross-file analysis:** the header value often arrives from a request
in a controller and is passed into a mailer helper a few hops later.
Trace each header field back: a `replyTo` that looks like a literal may
be `req.body.email`. Open the function that ultimately calls the SMTP /
`mail()` sink and check whether any sanitization happened in between.

## What to look for

- PHP `mail($to, $subject, $body, $headers)` where `$to`, `$subject`,
  or the 4th `$headers` argument contains request input:
  ```php
  $headers = "From: " . $_POST['email'] . "\r\n";
  mail($to, $subject, $body, $headers);
  ```
  A `From: a@b.com\r\nBcc: victim@x.com` value injects a Bcc.
- Python `email.message`/`MIMEText` headers or `smtplib.sendmail`
  built from user input:
  ```python
  msg['To'] = request.form['to']
  msg['Subject'] = request.form['subject']
  ```
  Modern `email.message.EmailMessage` rejects embedded newlines, but
  manually concatenated header strings or `add_header` with raw input
  do not.
- Node nodemailer fields taken straight from the request:
  ```js
  transport.sendMail({ to: req.body.to, subject: req.body.subject,
    replyTo: req.body.email, ... });
  ```
  Especially dangerous when the value is concatenated into a raw
  header via `headers: { 'X-Foo': req.body.x }`.

## True positive criteria

A finding is real when a request-derived value flows into an email
header (recipient, sender, subject, reply-to, or raw header) AND the
code does not strip or reject CR (`\r`, `%0d`) and LF (`\n`, `%0a`)
before the value reaches the mail sink.

You must be able to say: "I am an unauthenticated user submitting the
contact/signup form. I put `me@evil.com\r\nBcc: thousands@victims.com`
into the email field; the server emits that as two headers, so my Bcc
is delivered and the app becomes my mail relay." Name the attacker and
the trust boundary (the form field / request param). The burden is on
the code to show it sanitizes newlines or uses an API that rejects them.

## What to ignore

- Header values that are entirely constant or server-derived (a fixed
  From address, a templated subject with no user data).
- Code that explicitly strips/validates: `preg_replace('/[\r\n]/', '',
  $v)`, a regex that rejects `\r`/`\n`, or an email validator that
  forbids newlines and is applied to the actual value used.
- Python code using `EmailMessage` / `email.headerregistry` where the
  stdlib raises on embedded newlines (note: only the modern API; old
  `Header`/manual string building is still vulnerable).
- The user value placed only in the email *body* (not a header) — body
  injection is lower severity and not header injection (still flag if
  it crosses into a header via a templating quirk).
- Frameworks/mailers that document CRLF-stripping on header fields and
  the code uses those fields (not raw header concatenation).

## Examples

True positives:
```php
$headers = "From: {$_POST['email']}\r\nReply-To: {$_POST['email']}";
mail("support@x.com", $_POST['subject'], $_POST['msg'], $headers);
```
```python
msg = MIMEText(body)
msg['To'] = request.form['to']
smtp.sendmail(FROM, request.form['to'], msg.as_string())
```
```js
await transport.sendMail({
  to: req.body.to,
  replyTo: req.body.email,
  subject: req.body.subject,
});
```

False positives to skip:
```php
$email = $_POST['email'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) die();
$email = str_replace(["\r","\n"], '', $email);
mail($to, $subject, $body, "From: $email");
```
```js
const to = req.body.to.replace(/[\r\n]/g, '');
await transport.sendMail({ to, subject: "Welcome" });
```
```python
msg = EmailMessage()
msg['To'] = request.form['to']
```

If request input reaches a header field with no CRLF stripping or
newline-rejecting API on the path, treat it as a finding — the burden
is on the code to prove the newlines can't survive to the sink.
