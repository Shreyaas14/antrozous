# antrozous — end-to-end runbook

Send a message from one terminal session and receive+approve it in another,
through the relay, with strict isolation (declined messages never enter context).

## Components
- **Relay** (`src/antrozous/server.py`) — FastAPI store. Runs in the `.venv`.
- **MCP gate** (`mcp_gate.py`) — Claude Code UI: `send_message` + `check_inbox`
  tools. Pure stdlib; Claude launches it on system `python3`. Registered in `.mcp.json`.
- **CLI sender** (`send_cli.py`) — push a message without a Claude session.

Identity is resolved by the gate in four tiers (first hit wins):
1. env `AGENT_ID` — explicit override (used by self-tests / forcing a 2nd agent
   in one dir).
2. `./.antrozous/identity.json` — a directory that has deliberately opted OUT of
   the global identity, becoming its own agent with its own inbox.
3. `~/.antrozous/identity.json` — **the normal case.** One identity that follows
   you into every directory, so you are the same agent from anywhere.
4. generate — if none exist, mint tier 3 and reuse it forever.

Tier 3 is what makes the plugin behave identically from any directory. It is also
why the gate no longer creates a stray identity when launched without
`CLAUDE_PROJECT_DIR` (`send_cli.py`, `gate_selftest.py`, non-Claude-Code MCP
hosts): it falls back to the global file instead of the process's cwd.

`ANTROZOUS_HOME` relocates tier 3 — used by the test suite so it never touches a
real `~/.antrozous`, and useful for running two independent agents on one machine.

Generated global ids are `agent-<user>`; project-scoped ones are
`agent-<project>-<hex>`. `set_identity` writes tier 3 by default, and when the
current directory has a tier-2 file shadowing it, the popup discloses that
accepting will delete that file so the directory rejoins the global identity.
Pass `scope: "project"` to deliberately opt a directory out instead.

The naming popup is offered
**automatically at session start** until the id has been confirmed once. The hook
cannot raise the popup itself — MCP elicitation belongs to the gate and only happens
inside a tool call — so it emits `additionalContext` asking Claude to call
`set_identity` immediately, which is what shows the prompt.

`identity.json` carries a `confirmed` flag driving this:

| Popup outcome | `confirmed` | Next session |
|---|---|---|
| Accept | true | quiet |
| Decline (keep current id) | true | quiet |
| Dismissed without deciding | false | asks again |

Identities created before this flag existed count as unconfirmed, so they get the
prompt once. Exported `AGENT_ID` is never prompted, since writing the file cannot
change it.

To change an id later, ask Claude "set my agent id to <name>" (the gate's
`set_identity` tool). That raises an **approval popup**
with an editable name field — same out-of-band elicitation the inbox gate uses — so
the model can only *propose* an id and the user decides. Accept rewrites tier 2 and
takes effect on the next tool call, no restart. Declining leaves identity untouched.

The rename is gated because identity is what the relay routes on and what appears in
the recipient's `From:` line: a model that could rename its agent unprompted would
silently stop receiving on the old id, and could choose who others think it is.
If the client does not support elicitation, `set_identity` refuses rather than
renaming unconfirmed.

Note that tier 1 wins: if `AGENT_ID` is exported, `set_identity` writes the file but
the session keeps using the env value. The popup, the tool result, `whoami`, and the
SessionStart hook all say so explicitly.

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
