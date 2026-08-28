---
description: Stop listening for antrozous messages
allowed-tools: ["TaskStop", "Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py:*)"]
disable-model-invocation: true
---

# Go offline

Stop the user's antrozous inbox listener and keep it stopped.

1. **Record the opt-out first**, so the listener does not come back at the next
   session start even if the next step fails. Listening is on by default, so this
   writes an explicit `listening: false` rather than clearing anything — that
   tombstone is what keeps future sessions dark:

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/listener_state.py" off
   ```

   **If this exits non-zero**, the opt-out did not reach disk (an unwritable
   `~/.antrozous`, usually). Carry on to step 2 so the current session still goes
   quiet, but do **not** tell the user it sticks — say plainly that the next session
   will arm itself again until the permissions are fixed. Never report a durable
   opt-out you did not manage to store.

2. **Cancel the running Monitor(s).** The inbox listener is armed with a description
   of the form `antrozous inbox — <agent_id>`; there may be two (one for the session
   address, one for the account address). Call `TaskStop` on each task id from this
   session that matches.

3. **If you cannot find the task id** — it was armed before a context compaction, or
   in a different session — say so plainly. Tell the user the listener will not come
   back next session (step 1 already guarantees that), and that they can end the
   current watch with `/tasks`. Do not guess at task ids.

Confirm to the user that they are offline, that this sticks across future sessions
(they will not be re-armed automatically), and that `/antrozous:start` brings it
back. Messages sent to them while offline are **not lost** — they queue on the relay
and will surface the next time they check or go back online.
