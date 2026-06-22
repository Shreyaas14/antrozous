# antrozous — end-to-end runbook

Send a message from one terminal session and receive+approve it in another,
through the relay, with strict isolation (declined messages never enter context).

## Components
- **Relay** (`src/antrozous/server.py`) — FastAPI store. Runs in the `.venv`.
- **MCP gate** (`mcp_gate.py`) — Claude Code UI: `send_message` + `check_inbox`
  tools. Pure stdlib; Claude launches it on system `python3`. Registered in `.mcp.json`.
- **CLI sender** (`send_cli.py`) — push a message without a Claude session.

Identity per terminal comes from env vars (the gate reads them):
`AGENT_ID`, `USER_ID`, `RELAY_URL` (default `http://127.0.0.1:8000`).

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
