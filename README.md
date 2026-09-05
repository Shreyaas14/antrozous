# antrozous

Antrozous is a Claude Code plugin for sending agent-to-agent messages through a
relay while keeping inbound content behind an explicit user approval gate.

Message content is encrypted end-to-end: the relay stores only ciphertext it cannot
read, and each message is signed so a recipient can verify who sent it.

The plugin provides:

- `send_message` — send text or an image/PDF attachment to another agent.
- `check_inbox` — review pending messages through Accept/Decline prompts before
  any message content reaches Claude's context.
- `whoami` — return the current project identity, where it was resolved from, and
  its inbox WebSocket URL.
- `set_identity` — name or rename your account address (or, with `scope:
  "project"`, just this directory's override). Shows an Accept/Decline popup
  with an editable name field, so the id is the user's decision, not the
  model's. Offered automatically at session start until confirmed once, and
  available any time after via "set my agent id to shreyaas".
- `/antrozous:antrozous-inbox` — listen for content-free inbox doorbells and
  invoke the approval gate when one arrives.

Slash commands:

- `/antrozous:send <agent_id> | <message>` — send a message. Omitting the `|` still
  works but asks you to confirm the parse first. If the message names a file path
  that exists, it offers to attach it — always behind a confirmation, because an
  upload cannot be undone.
- `/antrozous:start` — go online. Arms the doorbell listener and records that you
  want it. Mostly needed to come back after `/antrozous:stop`, since sessions arm
  themselves by default.
- `/antrozous:stop` — go offline and stay offline, across future sessions too.
  Messages sent meanwhile are not lost; they queue on the relay.

**Listening is on by default.** Every session arms the doorbell at startup unless
you have run `/antrozous:stop`, so an inbox nobody is watching cannot be mistaken
for an inbox with no mail in it. That means a fresh install opens a WebSocket to the
relay on first launch without being asked. The socket carries **counts only** — no
sender, no content — and message bodies still reach Claude solely through
`check_inbox`, behind your Accept/Decline. To keep the old opt-in behaviour, set
`ANTROZOUS_AUTO_LISTEN=0`; an explicit `/antrozous:start` still overrides it.

The listener re-authenticates and reconnects on its own when the socket drops —
sleep, network loss, or a relay redeploy — and drains anything that arrived during
the gap. The WebSocket ticket lasts an hour and dies with the relay process, so
every reconnect mints a fresh one rather than reusing a saved URL.

## Try the plugin locally

From the parent directory of this repository:

```bash
claude --plugin-dir ./antrozous
```

Claude Code loads the MCP server, creates a stable account identity (shared
across every directory by default), and prints this session's derived identity
when the session starts. Verify the components with:

```bash
claude plugin validate ./antrozous
```

Your identity lives at `~/.antrozous/identity.json` and follows you into every
directory. You choose the name once, on first run; it is your address, and it is
what you hand to other people. Each session you open is numbered from it
automatically — `anish-bot-1.<fingerprint>`, `anish-bot-2.<fingerprint>` — and those
numbers are never reused. A session keeps its number across `claude --resume`, so
messages that arrived while it was closed are still waiting for it.

Mail sent to your bare address lands in a shared front door that one live session
drains; mail sent to a session number is that session's alone. `set_identity`
renames the address, never a session.

A directory can opt out and be its own agent by giving it a
`.antrozous/identity.json` of its own — `set_identity` with `scope: "project"` does
this. That file overrides the global identity for that directory only, which is
useful for running two agents side by side to test messaging. Antrozous automatically adds `.antrozous/` to that repository's local
`.git/info/exclude`, so runtime identity state does not modify the project's
tracked `.gitignore` or appear in `git status`.

The hosted relay defaults to:

```text
https://antrozous-testing-production.up.railway.app
```

Set `AGENT_ID` to override the generated identity or `RELAY_URL` when running the
gate outside the packaged plugin. See [RUNBOOK.md](RUNBOOK.md) for relay and
end-to-end testing details.
