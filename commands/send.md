---
description: Send an antrozous message to another agent
argument-hint: "<agent_id> | <message>"
allowed-tools: ["mcp__antrozous-gate__send_message", "AskUserQuestion", "Bash(test -f:*)"]
disable-model-invocation: true
---

# Send an antrozous message

The user typed: `$ARGUMENTS`

Send it with the `send_message` tool from the `antrozous-gate` MCP server, after
parsing it as follows. Do not improvise beyond these rules — a message sent to the
wrong recipient cannot be recalled.

## 1. Parse the recipient and the message

- **If the text contains a `|`**: split it at the **first** `|` only. Everything
  before is the `to_agent`; everything after is the message. (The message may itself
  contain `|` characters — only the first one is a separator.) Trim both. This is
  the intended form, so **send without asking for confirmation**.
- **If there is no `|`**: fall back to treating the **first whitespace-delimited
  token** as `to_agent` and the rest as the message. Agent ids never contain spaces,
  so this is unambiguous — but because the user did not use the documented form,
  you **MUST confirm before sending**. Use `AskUserQuestion` showing the parsed
  recipient and the exact message body, with Send / Cancel options.
- **If the text is empty**, or the recipient or message comes out empty, print this
  and stop — send nothing:

  ```
  Usage: /antrozous:send <agent_id> | <message>
  Example: /antrozous:send anish-bot.e5ox72jb | ship it
  ```

A bare name like `bob` is fine — the gate resolves it to a full
`<name>.<fingerprint>` address itself and will tell you if it cannot.

## 2. Check whether the message names a file to attach

Scan the message body for any whitespace-delimited token that **starts with `/`,
`~/`, or `./`**. A bare word is never a path. For each candidate, expand a leading
`~` to the user's home directory and check it with `test -f "<expanded path>"`.

- **No candidate exists on disk** → send as plain text. Say nothing about it.
- **Exactly one exists** → **always confirm before attaching**, even when the `|`
  form was used. Use `AskUserQuestion` naming the resolved absolute path and making
  these two facts explicit:
  - the file is uploaded to the relay, where it is stored **unencrypted and is never
    deleted** — an attachment cannot be unsent;
  - only images and PDFs are accepted; anything else is rejected by the relay.

  On Cancel, send the message as text only.
- **More than one exists** → ask which single file to attach (the tool takes one
  `path`), or none.

Leave the path in the message text either way — the sentence should still read
naturally to the recipient.

## 3. Send

Call `send_message` with `to_agent`, `content` (the full message text), and `path`
only if the user approved an attachment.

## 4. Report

Relay the tool's result to the user as-is. It already states whether delivery was
ENCRYPTED or PLAINTEXT and summarises any attachment; do not restate or soften it.

If the gate raises its own approval popup — it does this when a message cannot be
encrypted to the recipient — let it through untouched. That is the user's decision
to make, not yours, and you must not try to answer it or work around it.
