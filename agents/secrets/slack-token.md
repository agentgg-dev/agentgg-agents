---
slug: slack-token
name: Slack Token / Webhook Exposure
description: 'Hardcoded Slack bot tokens (xoxb-), user tokens (xoxp-), and incoming webhook URLs in source or config. A bot token can read channel history and DMs; a user token acts as the authorizing user; a webhook URL posts arbitrary messages to a channel.'
version: 0.1.0
author: agentgg
noiseTier: precise
where:
  filePatterns:
    - '**/*'
  excludePatterns:
    - '**/node_modules/**'
    - '**/vendor/**'
    - '**/dist/**'
    - '**/.next/**'
    - '**/build/**'
    - '**/target/**'
  preFilter:
    - regex: 'xoxb-[0-9A-Za-z\-]{52}'
      label: Slack bot token (xoxb-)
    - regex: 'xoxp-[0-9A-Za-z\-]{74}'
      label: Slack user token (xoxp-)
    - regex: 'xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}'
      label: Slack legacy token structured format
    - regex: 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
      label: Slack incoming webhook URL
    - regex: 'https?://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{43,46}'
      label: Slack webhook URL (broad)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Slack credentials.

## Credential types and risk

**Bot token (`xoxb-...`):** Authenticates as a Slack app/bot. Permissions depend on the OAuth scopes the app was granted. With `channels:read` and `messages:read`, an attacker can exfiltrate all message history from channels the bot is in. With `chat:write`, they can impersonate the bot and post messages. Common bot tokens in production apps have broad access.

**User token (`xoxp-...`):** Authenticates as a specific Slack user. Acts as that user across all workspaces they belong to. This is more dangerous than a bot token because it carries the user's full identity — DMs, private channels, files, reactions, and workspace admin actions if the user is an admin.

**Incoming webhook URL (`https://hooks.slack.com/services/...`):** A one-way credential that lets anyone post messages to a specific Slack channel. Attacker can send phishing messages, social engineering attempts, or malicious links to the channel's audience.

## Cross-file analysis

When a token is found, look for:
1. The Slack API methods called (`conversations.history`, `chat.postMessage`, `users.list`, `admin.*`) — determines what the token can access
2. Whether the token is used in a customer-facing or internal-only context
3. Any workspace or channel name that reveals sensitivity of the data accessible

## True positive criteria

Flag when ALL hold:
1. The value matches the `xoxb-`, `xoxp-`, or webhook URL pattern
2. It is a string literal, not an environment variable reference (`process.env.SLACK_BOT_TOKEN`)
3. It is not a placeholder or example value (all same character, `xoxb-XXXX...`, Slack's own documentation examples)

Webhook URLs are always a finding when hardcoded — they are meant to be kept private despite being "just" a URL.

## What to ignore

- Environment variable references
- Values that are clearly masked or redacted
- Test files that mock the Slack SDK with fake token strings used only in unit tests (check that no real HTTP calls are made)

## Examples

True positives:
```ts
const client = new WebClient('xoxb-<bot-token>');
```
```yaml
SLACK_WEBHOOK_URL: https://hooks.slack.com/services/<T-id>/<B-id>/<secret>
```

False positives to skip:
```ts
const client = new WebClient(process.env.SLACK_BOT_TOKEN);
```

Note the token type (bot vs. user vs. webhook), which Slack API methods the code calls, and whether the workspace appears to be a production workspace.
