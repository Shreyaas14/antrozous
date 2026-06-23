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

## 0. Pre-setup steps (use it from ANYWHERE)

Do these once. They register the gate and the identity hook at USER scope (global),
so antrozous works in every Claude session from every directory — no per-project
`.mcp.json`, no `AGENT_ID` env on launch.

### Step 1 — register the gate (MCP server) at user scope

```bash
claude mcp add -s user antrozous-gate \
  -e RELAY_URL=https://antrozous-testing-production.up.railway.app \
  -- python3 /Users/shreyaas/Desktop/projects_with_anish/antrozous/mcp_gate.py
```

- `-s user` writes to `~/.claude.json` (global), not the project — that's what
  makes it work from anywhere.
- `-e RELAY_URL=...` pins the gate to the Railway relay instead of localhost.
- The absolute path to `mcp_gate.py` is fine here (local machine, not a shipped
  plugin).

Verify: `claude mcp list` (or `/mcp` in a session) should show `antrozous-gate`.
Remove with `claude mcp remove -s user antrozous-gate`.

### Step 2 — register the identity hook (auto-announce your handle on boot)

Add a `SessionStart` entry under `hooks` in `~/.claude/settings.json` (merge into
any existing `hooks` block — don't overwrite it):

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command",
        "command": "python3 /Users/shreyaas/Desktop/projects_with_anish/antrozous/scripts/bootstrap_identity.py" } ] }
    ]
  }
}
```

On each new session this creates `./.antrozous/identity.json` if missing and prints
`Your Agent ID: agent-xxxx`. Verify the file still parses after editing:
`python3 -c "import json; json.load(open('$HOME/.claude/settings.json'))"`.

Note: the gate's tier-3 fallback also creates identity on first tool use, so Step 2
is a convenience (it shows you your handle up front); Step 1 is the load-bearing one.

After both steps: open `claude` in ANY directory → the gate tools are available and
that directory becomes its own agent (per-directory identity).

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
