# antrozous — end-to-end runbook

Send a message from one terminal session and receive+approve it in another,
through the relay, with strict isolation (declined messages never enter context).

## Components
- **Relay** (`src/antrozous/server.py`) — FastAPI store. Runs in the `.venv`.
- **MCP gate** (`mcp_gate.py`) — Claude Code UI: `send_message` + `check_inbox`
  tools. Pure stdlib; Claude launches it on system `python3`. Registered in `.mcp.json`.
- **CLI sender** (`send_cli.py`) — push a message without a Claude session.

Identity is resolved by the gate in three tiers (first hit wins):
1. env `AGENT_ID` — explicit override (used by self-tests / forcing a 2nd agent
   in one dir).
2. `./.antrozous/identity.json` — the saved per-directory handle (normal case).
3. generate — if neither exists, mint `agent-<hex>`, write it, and reuse it.

So identity is now per-directory and auto-created; you no longer have to pass
`AGENT_ID` on every launch. `USER_ID` still falls back to `$USER`; `RELAY_URL`
defaults to `http://127.0.0.1:8000` but is pinned to Railway by the registration
below.

## 0. Load the Claude plugin

From the directory containing this repository:

```bash
claude --plugin-dir ./antrozous
```

The plugin's portable `.mcp.json` starts the gate via `${CLAUDE_PLUGIN_ROOT}` and
its `SessionStart` hook creates and announces the per-project identity. No absolute
installation path, user-scoped MCP registration, or manual settings hook is needed.

For development, validate the package before launching it:

```bash
claude plugin validate ./antrozous
```

When an identity is created inside a Git repository, antrozous adds `.antrozous/`
to the repository's local `.git/info/exclude`. The identity therefore stays local
and does not appear in `git status` or change the repository's tracked `.gitignore`.

## 1. Start the relay (Terminal 1)
```bash
cd ~/antrozous
PYTHONPATH=src .venv/bin/python -m uvicorn antrozous.server:app --host 127.0.0.1 --port 8000
# leave running; check: curl -s http://127.0.0.1:8000/health
```

## 2. Receiver (Terminal 2 = agent-B)
```bash
cd ~/antrozous
AGENT_ID=agent-B claude
```
- Approve the `antrozous-gate` MCP server when prompted (one-time trust).
- Say: **check my inbox**

## 3. Sender — two ways

**A. From a Claude session (Terminal 3 = agent-A):**
```bash
cd ~/antrozous
AGENT_ID=agent-A claude
# then: "send a message to agent-B saying hello from A"
```

**B. From any terminal, no Claude (the quick way):**
```bash
cd ~/antrozous
python3 send_cli.py agent-B "hello from the CLI" --from-agent agent-A
```

## 4. Verify (back in Terminal 2)
Say **check my inbox** again → an approval prompt shows the message.
- **Decline** → model gets nothing (content stays out of context).
- **Accept**  → model receives it wrapped as `<external_message …>` untrusted data.
Ask afterward "what did that say?" to confirm decline really withheld it.

## Offline proof (no Claude needed)
```bash
python3 gate_selftest.py     # drives the gate against the live relay
```

## Notes / limits (MVP)
- In-memory relay; messages are lost if the relay restarts (persistence = follow-up).
- `check_inbox` consumes the batch it showed; messages arriving mid-check wait for
  the next check.
- No signatures yet — plaintext pipe. Ed25519 sign/verify is the next layer.
- Reset an inbox: `curl -X POST "http://127.0.0.1:8000/inbox/agent-B/consume?count=-1"`
