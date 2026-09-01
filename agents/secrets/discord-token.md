---
slug: discord-token
name: Discord Bot Token Exposure
description: 'Hardcoded Discord bot tokens (64 hex chars near "discord") in source or config. A leaked token gives full control of the bot: send messages to any guild channel, access member lists, and perform any action the bot has permissions for.'
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
    - regex: '(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s'']|[\s"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:''|"|\s|=|`){0,5}([a-f0-9]{64})(?:[''"\n\r\s`;]|$)'
      label: Discord token (64 hex near discord keyword)
    - regex: '(?i)discord.{0,30}[=:][''"\s]{0,3}[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}'
      label: Discord token dot-separated format
references:
  - CWE-798
  - CWE-540
  - 'OWASP-A02:2021'
---

You are reviewing source code and config files for hardcoded Discord bot tokens.

## Token format

Discord bot tokens use two main formats:
1. **Hex format:** 64 lowercase hexadecimal characters, typically assigned next to a variable or config key containing "discord" or "token"
2. **Dot-separated format:** three base64url segments separated by dots — `[user_id].[timestamp].[hmac]` — where the first segment starts with `M` or `N` and is about 24 characters, the second is about 6, and the third is about 27

## Risk

An attacker with a Discord bot token can:
- Send messages to any channel the bot has access to — enables phishing or social engineering of guild members
- Read message history in all channels the bot can view
- Kick, ban, or manage members if the bot has those permissions
- Modify channel settings, roles, or server configuration if the bot has admin permissions
- Use the token to enumerate all guilds the bot is in and their members

## Cross-file analysis

When a token is found, look for:
1. Guild IDs or channel IDs the bot interacts with — reveals the scope of potential damage
2. Bot permission intents (`GUILD_MEMBERS`, `MESSAGE_CONTENT`, `GUILD_MESSAGES`) — determines what data the bot can access
3. Whether the bot has admin or elevated permissions in any guild

## True positive criteria

Flag when ALL hold:
1. The value matches the token format and appears near Discord-related code or a `discord`/`token`/`BOT_TOKEN` variable name
2. It is a string literal, not an environment variable reference (`process.env.DISCORD_TOKEN`, `process.env.BOT_TOKEN`)
3. It is not a placeholder: all same character, documentation example, or clearly fake value

## What to ignore

- Environment variable references: `process.env.DISCORD_TOKEN`, `client.login(process.env.BOT_TOKEN)`
- Webhook URLs (handled separately) — those only post to one channel; bot tokens grant broader access
- Test/mock values that clearly don't match the real token format

## Examples

True positives:
```ts
client.login('<64-hex-discord-token>');
```
```yaml
DISCORD_TOKEN: <64-hex-discord-token>
```

False positives to skip:
```ts
client.login(process.env.DISCORD_TOKEN);
```

Note the bot's permissions and which guilds it belongs to if discoverable from the code, to assess blast radius.
