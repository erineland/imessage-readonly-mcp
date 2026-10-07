# iMessage MCP server — read-only

Lets Claude **read** (never send) the iMessages and SMS that the Messages app already
stores on your Mac.

- **Runtime:** `/usr/bin/python3`, standard library only — no dependencies
- **Reads:** `~/Library/Messages/chat.db`, plus the local Contacts databases for names
- **Needs:** Full Disk Access for the app that launches it (e.g. your terminal), because macOS protects `~/Library/Messages`

## Tools

| Tool | What it does |
|---|---|
| `imessage_list_chats` | Conversations, most recent first, with unread counts |
| `imessage_read_chat` | Messages from one conversation (`chat` = name or `id:N`), optional `since`/`until` |
| `imessage_search` | Text search across conversations, newest first |
| `imessage_recent` | "Catch me up" — messages received in the last N hours, grouped by chat |

## Why it's safe

**Read-only is enforced four ways:**
1. There is no sending code, and networking modules (`socket`, `urllib`, `http`, `ssl`, `subprocess`…) are **blocked from being imported** at runtime.
2. Databases are opened in SQLite **read-only mode** — the engine itself refuses writes.
3. `PRAGMA query_only=ON` — an independent second write lock.
4. The source contains only `SELECT` statements.

## Privacy controls

- **`excluded_chats.txt`** — conversations Claude must never read: a name, `id:N`, a phone number or an email handle, one per line.
- **Phone numbers and email addresses are never shown.** Contacts appear by name; unknown numbers are masked (`+44 •••• •••123`). Alphanumeric business sender IDs (e.g. `Monzo`) are shown.
- **One-time codes are redacted.** Messages that look like verification/login codes have their digits replaced with `••••`, so 2FA codes never reach the model.
- **`audit.log`** records every read: time, tool, arguments, number of results — **never the message text**.
- Text only: attachments appear as `[📎 attachment]` and are never opened.
- Every result is prefixed as **untrusted third-party content**, so the model treats messages as data, not instructions.

## Install (Claude Code)

```bash
claude mcp add imessage -s user -e IMESSAGE_ME_NAME="Your Name" -- /usr/bin/python3 /path/to/imessage_mcp.py
```

Optional: `IMESSAGE_TZ` (default `Europe/London`).

## Notes

Recent macOS versions store most message text in `attributedBody` (an archived
`NSAttributedString`) rather than `text`. The server extracts the plain string from that
blob directly — no PyObjC needed.

MIT licensed.
