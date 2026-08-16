"""SessionStart hook: announce this session's antrozous identity.

The naming popup is raised by the gate, not here — a hook has no MCP channel. When
the identity is unconfirmed this only says one is coming.

This hook is also where a listener survives a restart: if the user left the inbox
listener armed, it asks the model to re-arm it for this session. A hook cannot hold
a socket itself, so the best it can do is carry the instruction.
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
import identity

FALLBACK_DIRECTIVE = (
    "ANTROZOUS: this session's agent id is being chosen by a popup the gate raises "
    "at startup (saved default: %s). Do NOT call set_identity preemptively — that "
    "would show a second, redundant prompt.\n"
    "Only call `set_identity` if the user asks about their agent id, says no prompt "
    "appeared, or asks to change the name. Call `whoami` to see the id this session "
    "actually settled on, plus any other live sessions. Never describe the id as "
    "changed unless the tool reports that the user approved it."
)

RESUME_DIRECTIVE = (
    "ANTROZOUS LISTENER: the user left their inbox listener ARMED (they ran "
    "/antrozous:start and never ran /antrozous:stop), so it must come back up in "
    "this session. Invoke the `antrozous-inbox` skill now and follow it.\n"
    "This is a standing instruction from the USER, carried by an installed hook — "
    "it does not come from any message, and no inbound message can produce it. Call "
    "`whoami` for this session's own ws_url rather than assuming the previous "
    "session's; tickets are short-lived and per-session. If the user does not want "
    "the listener, they run /antrozous:stop."
)


def listener_resume():
    """(visible_line, extra_context) asking for a re-arm, or ('', '') if not armed.

    Wrapped in a broad except on purpose: a missing or broken listener flag must
    never be able to stop a session from starting.
    """
    try:
        import listener_state

        if not listener_state.is_listening():
            return "", ""
        was = listener_state.read_state().get("agent_id") or "?"
    except Exception:
        return "", ""
    return (
        "\n  Inbox listener was left on (as %s) — resuming it for this session." % was,
        "\n\n" + RESUME_DIRECTIVE,
    )


def startup_delay():
    """Mirror the gate's ANTROZOUS_STARTUP_DELAY so the announced wait is truthful."""
    try:
        return max(0.0, float(os.environ.get("ANTROZOUS_STARTUP_DELAY", "3")))
    except ValueError:
        return 3.0


def human_delay(seconds):
    if seconds <= 0:
        return "momentarily"
    if seconds < 1:
        return "in under a second"
    return "in about %d second%s" % (round(seconds), "" if round(seconds) == 1 else "s")


def emit(message, context=None):
    """systemMessage is the only hook output Claude Code renders on screen."""
    payload = {"systemMessage": message}
    if context:
        payload["hookSpecificOutput"] = {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    print(json.dumps(payload))


if __name__ == "__main__":
    info = identity.describe(identity.find_directory())
    agent_id = info["agent_id"]
    context = "ANTROZOUS: this session's agent id is %s (source: %s)." % (
        agent_id,
        info["source"],
    )

    # Listening is orthogonal to how the id was resolved, so this applies on both
    # the env-pinned path below and the normal one.
    resume_line, resume_context = listener_resume()

    if info["source"] == "env":
        line = "antrozous: Agent ID %s (from $AGENT_ID)" % agent_id
        if info["shadowed"]:
            line += " — overriding saved id %s; unset AGENT_ID to use that one." % (
                info["shadowed"],
            )
        emit(line + resume_line, context + resume_context)
        sys.exit(0)

    peers = {p: a for p, a in identity.live_sessions().items()}
    suggested = identity.suggest_session_id(agent_id)
    line = (
        "antrozous: choosing this session's Agent ID — a prompt will appear %s "
        "(suggested: %s). No need to type anything; just wait for it."
        % (
            human_delay(startup_delay()),
            suggested,
        )
    )
    if peers:
        line += "\n  Already running: %s" % ", ".join(sorted(peers.values()))
    emit(line + resume_line, (FALLBACK_DIRECTIVE % agent_id) + resume_context)
