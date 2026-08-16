---
description: Stop listening for antrozous messages
allowed-tools: ["TaskStop", "Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py:*)"]
disable-model-invocation: true
---

# Go offline

Stop the user's antrozous inbox listener and keep it stopped.

1. **Clear the flag first**, so the listener does not come back at the next session
   start even if the next step fails:

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py" off
   ```

2. **Cancel the running Monitor(s).** The inbox listener is armed with a description
   of the form `antrozous inbox — <agent_id>`; there may be two (one for the session
   address, one for the account address). Call `TaskStop` on each task id from this
   session that matches.

3. **If you cannot find the task id** — it was armed before a context compaction, or
   in a different session — say so plainly. Tell the user the listener will not come
   back next session (step 1 already guarantees that), and that they can end the
   current watch with `/tasks`. Do not guess at task ids.

Confirm to the user that they are offline and that `/antrozous:start` brings it
back. Messages sent to them while offline are **not lost** — they queue on the relay
and will surface the next time they check or go back online.
