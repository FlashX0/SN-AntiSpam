# Discord Honeypot Bot

A Discord moderation bot that removes and enforces against messages in the `type-here-to-get-kicked` honeypot channel and can optionally scan every channel for the configured scam signatures. It examines text, blacklisted domains, and attached screenshots using local Tesseract OCR.

## Before starting

1. In the Discord Developer Portal, enable **Message Content Intent** for the bot application.
2. Invite the bot with **View Channels**, **Read Message History**, **Send Messages**, **Manage Messages**, and **Kick Members** permissions. Use **Ban Members** instead of Kick Members if `ENFORCEMENT_ACTION=ban`.
3. Put the real token in `.env` as `DISCORD_BOT_TOKEN=...`; do not send it in chat or commit it.

## Run

```bash
./.venv/Scripts/python.exe main.py
```

## Configuration

- `ENFORCE_ANY_TRAP_MESSAGE=true`: any human message in the honeypot triggers enforcement.
- `SCAN_ALL_CHANNELS=false`: change to `true` to scan scam signatures outside the honeypot channel too.
- `ENFORCEMENT_ACTION=kick`: set `ban` if you prefer bans.
- `TESSERACT_CMD`: optional override for a nonstandard Tesseract install.

Tesseract was installed at the normal Windows location and is auto-detected by the bot.
