#!/usr/bin/env python3
"""Whether this device wants its antrozous inbox listened to.

Listening is ON BY DEFAULT: a doorbell is the point of the plugin, and an inbox
nobody is watching looks exactly like an inbox with no mail in it. So the flag is
tri-state, and its ABSENCE means "arm it":

    (no file)              -> auto-arm; nobody has expressed a preference yet
    {"listening": true}    -> arm; the user ran /antrozous:start
    {"listening": false}   -> stay dark; the user ran /antrozous:stop

That last state is why `/antrozous:stop` writes a tombstone instead of deleting the
file. Under a default of ON, deleting would mean "go offline until the next session
starts", which is not what going offline promises.

`is_listening()` answers "did the user explicitly arm this?"; `wants_listener()`
answers "should a session come up listening?" — the hook asks the latter.

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

    Anything we cannot parse reads as {} rather than raising, and {} falls through
    to the default, which `wants_listener` treats as "arm it". The catch is wider
    than identity._read_json's on purpose: that helper only handles a missing file
    and bad JSON, but this path also meets unreadable permissions, a directory left
    in the flag's place, and non-UTF-8 bytes. Under a default of ON those would not
    merely raise — they would decide, silently, that the user is unreachable.
    """
    try:
        state = identity._read_json(state_path())
    except (OSError, ValueError):
        # ValueError covers UnicodeDecodeError; OSError covers PermissionError and
        # IsADirectoryError.
        return {}
    # Valid JSON that is not an object (a bare list or string) parses fine and then
    # blows up on the first .get(), so it is discarded here rather than at each use.
    return state if isinstance(state, dict) else {}


def is_listening():
    """True only when the user explicitly armed the listener."""
    return bool(read_state().get("listening"))


def wants_listener():
    """Whether a new session should come up listening.

    Only an explicit `{"listening": false}` says no. A missing file is a user who
    has never chosen, and an unreadable one is a user whose choice we lost — both
    fall back to the default rather than silently going dark.
    """
    state = read_state()
    if "listening" not in state:
        return True
    return bool(state.get("listening"))


def preference_source():
    """"flag" when a stored choice decided it, "default" when nothing did."""
    return "flag" if "listening" in read_state() else "default"


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
    """Stop wanting the inbox watched, and keep it stopped.

    Writes an explicit `listening: false` rather than removing the file: absence
    means auto-arm, so deleting here would bring the listener straight back at the
    next session start.
    """
    record = {
        "listening": False,
        "agent_id": read_state().get("agent_id"),
        "stopped_at": str(datetime.now()),
    }
    os.makedirs(identity.global_dir(), exist_ok=True)
    identity._write_json(state_path(), record)
    return record


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    command = argv[0]

    if command == "on":
        if len(argv) < 2 or not argv[1].strip():
            print("usage: listener_state.py on <agent_id>", file=sys.stderr)
            return 2
        try:
            record = set_listening(argv[1])
        except OSError as e:
            print("could not record the listener flag: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps(record))
        return 0

    if command == "off":
        # A failure here is not cosmetic: with listening ON BY DEFAULT, an opt-out
        # that did not reach disk means the next session arms itself again. Say so
        # rather than printing a success the user cannot rely on.
        try:
            record = clear_listening()
        except OSError as e:
            print("could not record the opt-out: %s" % e, file=sys.stderr)
            return 1
        print(json.dumps(record))
        return 0

    if command == "status":
        state = read_state()
        print(
            json.dumps(
                {
                    "listening": bool(state.get("listening")),
                    "wants_listener": wants_listener(),
                    "source": preference_source(),
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
