#!/usr/bin/env python3
"""Whether this device wants its antrozous inbox listened to.

The flag is what makes a listener survive a restart: `/antrozous:start` sets it,
`/antrozous:stop` clears it, and the SessionStart hook reads it to decide whether a
new session should re-arm the doorbell socket on its own.

Deliberately NOT an MCP tool. Arming a listener is the user's decision, so the
switch is reachable from a slash command and a hook, never from a model turn.

  usage: python3 listener_state.py on <agent_id>
         python3 listener_state.py off
         python3 listener_state.py status      # prints JSON, always exit 0
"""

import json
import os
import sys

from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import identity


def state_path():
    return os.path.join(identity.global_dir(), "listener.json")


def read_state():
    """The stored record, or {} when absent or unreadable.

    A corrupt file reads as 'not listening' rather than raising: a broken flag must
    never be able to stop a session from starting.
    """
    return identity._read_json(state_path()) or {}


def is_listening():
    return bool(read_state().get("listening"))


def set_listening(agent_id):
    """Record that this device wants its inbox watched, as `agent_id`."""
    if not (isinstance(agent_id, str) and agent_id.strip()):
        raise ValueError("set_listening requires a non-empty agent id")
    previous = read_state()
    record = {
        "listening": True,
        "agent_id": agent_id.strip(),
        # Kept from the first arm so the flag shows when listening actually began,
        # not when it was last refreshed by a reconnect.
        "started_at": previous.get("started_at") or str(datetime.now()),
    }
    os.makedirs(identity.global_dir(), exist_ok=True)
    identity._write_json(state_path(), record)
    return record


def clear_listening():
    """Stop wanting the inbox watched. Absent file is already the desired state."""
    try:
        os.unlink(state_path())
    except OSError:
        pass


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    command = argv[0]

    if command == "on":
        if len(argv) < 2 or not argv[1].strip():
            print("usage: listener_state.py on <agent_id>", file=sys.stderr)
            return 2
        record = set_listening(argv[1])
        print(json.dumps(record))
        return 0

    if command == "off":
        clear_listening()
        print(json.dumps({"listening": False}))
        return 0

    if command == "status":
        state = read_state()
        print(
            json.dumps(
                {
                    "listening": bool(state.get("listening")),
                    "agent_id": state.get("agent_id"),
                    "started_at": state.get("started_at"),
                }
            )
        )
        return 0

    print("unknown command: %s" % command, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
