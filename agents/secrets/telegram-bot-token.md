---
slug: telegram-bot-token
name: Telegram Bot Token Exposure
description: 'Hardcoded Telegram bot tokens (\d+:AA[a-zA-Z0-9_-]{32,33}) in source or config. A leaked token lets an attacker impersonate the bot, read all messages it receives, send messages to any chat it belongs to, and modify bot settings.'
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
    - regex: '\b(\d{8,10}:AA[a-zA-Z0-9_-]{32,33})\b'
      label: Telegram bot token (numeric ID:AA...)
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Telegram bot tokens.

## Token format

Telegram bot tokens have a fixed format: `{bot_id}:AA{random_string}` where:
- `bot_id` is a numeric ID (8-10 digits)
- `:AA` is a fixed separator
- The random portion is 32-33 base64url characters

Example: `<bot-id>:AA<32-char-token>`

## Risk

An attacker with a Telegram bot token can:
- Impersonate the bot and send messages to every chat and group the bot is in
- Read all messages directed at the bot (webhooks / polling would be redirected to the attacker)
- Access the bot's group membership, admin rights in groups, and conversation history
- Modify webhook settings to intercept all incoming messages — effectively hijacking all bot communications
- If the bot has admin privileges in channels or groups: post announcements, add/remove members, change group settings

## Cross-file analysis

When a token is found, look for:
1. Webhook URL configuration — an attacker who changes the webhook can silently intercept all bot traffic
2. What chats/channels the bot is in — determines the audience exposed to impersonated messages
3. Whether the bot stores or forwards sensitive user data received via Telegram

## True positive criteria

Flag when ALL hold:
1. The value matches `\d{8,10}:AA[a-zA-Z0-9_-]{32,33}` — this format is unambiguous
2. It is a string literal, not an environment variable reference (`process.env.TELEGRAM_BOT_TOKEN`, `os.environ.get('BOT_TOKEN')`)
3. It is not a placeholder: documentation example bots, all same characters, Telegram's own `1234567890:AABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB` test format

## What to ignore

- Environment variable references
- The Telegram Bot API URL pattern with a token: check if the URL is constructed from a variable reference vs. a hardcoded token
- Test/mock tokens that clearly don't follow the real format

## Examples

True positives:
```ts
const bot = new TelegramBot('<bot-id>:AA<32-char-token>', { polling: true });
```
```python
bot = telebot.TeleBot("<bot-id>:AA<32-char-token>")
```
```yaml
TELEGRAM_TOKEN: <bot-id>:AA<32-char-token>
```

False positives to skip:
```ts
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
```

Note what the bot does (handles payments, stores user data, sends notifications) to assess the sensitivity of intercepted messages.
