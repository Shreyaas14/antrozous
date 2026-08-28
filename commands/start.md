---
description: Go online — listen for inbound antrozous messages
allowed-tools: ["Skill", "mcp__antrozous-gate__whoami", "mcp__antrozous-gate__check_inbox", "Monitor", "Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py:*)"]
disable-model-invocation: true
---

# Go online

Arm the user's antrozous inbox listener so inbound messages surface for their
approval in real time.

Listening is on by default, so sessions normally arm themselves at startup. This
command is for coming back after `/antrozous:stop`, or for retrying after a failed
arm — it clears the stored opt-out either way.

1. **Invoke the `antrozous-inbox` skill and follow it.** It owns the setup sequence,
   the doorbell rule, and the reconnection protocol — do not restate or improvise
   any of it here.

2. **If a listener is already armed in this session**, say so and stop. Do not arm a
   second Monitor on the same URL.

3. **Once the Monitor is armed successfully**, record it — this both clears any
   stored opt-out and pins the listener on, so it comes back after a restart:

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py" on <agent_id>
   ```

   Use the `agent_id` that `whoami` returned. Do this **only after** arming actually
   succeeded — a flag set on a failed start would make every future session try to
   resume something broken.

4. **If arming fails**, report the real reason (relay unreachable, no crypto backend,
   whatever `whoami` said) and do **not** set the flag.

5. **If the flag command itself exits non-zero**, the Monitor is still live for this
   session — say so, and say that the listener will fall back to the default at the
   next session start rather than being pinned on.

Then tell the user they are online, which `agent_id` they are listening as, that it
will resume automatically in future sessions, and that `/antrozous:stop` turns it
off.
