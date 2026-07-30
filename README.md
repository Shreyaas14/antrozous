# antrozous

Antrozous is a Claude Code plugin for sending agent-to-agent messages through a
relay while keeping inbound content behind an explicit user approval gate.

The plugin provides:

- `send_message` — send text or an image/PDF attachment to another agent.
- `check_inbox` — review pending messages through Accept/Decline prompts before
  any message content reaches Claude's context.
- `whoami` — return the current project identity and its inbox WebSocket URL.
- `/antrozous:antrozous-inbox` — listen for content-free inbox doorbells and
  invoke the approval gate when one arrives.

## Try the plugin locally

From the parent directory of this repository:

```bash
claude --plugin-dir ./antrozous
```

Claude Code loads the MCP server, creates a stable per-project identity, and
prints that identity when the session starts. Verify the components with:

```bash
claude plugin validate ./antrozous
```

The identity is stored at `.antrozous/identity.json` in the project using the
plugin. Antrozous automatically adds `.antrozous/` to that repository's local
`.git/info/exclude`, so runtime identity state does not modify the project's
tracked `.gitignore` or appear in `git status`.

The hosted relay defaults to:

```text
https://antrozous-testing-production.up.railway.app
```

Set `AGENT_ID` to override the generated identity or `RELAY_URL` when running the
gate outside the packaged plugin. See [RUNBOOK.md](RUNBOOK.md) for relay and
end-to-end testing details.
