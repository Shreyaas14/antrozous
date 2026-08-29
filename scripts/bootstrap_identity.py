"""SessionStart hook: announce this session's antrozous identity.

The naming popup is raised by the gate, not here — a hook has no MCP channel. When
the identity is unconfirmed this only says one is coming.

This hook is also where the inbox listener comes up. Listening is on by default, so
there are two cases and one mechanism: the user explicitly armed it and we resume,
or nobody has chosen yet and we arm it for the first time. Either way a hook cannot
hold a socket itself — the best it can do is carry the instruction, and the model
arms the Monitor on its first turn.
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

AUTOSTART_DIRECTIVE = (
    "ANTROZOUS LISTENER: inbox listening is ON BY DEFAULT and this device has not "
    "opted out, so bring the listener up in this session. Invoke the "
    "`antrozous-inbox` skill now and follow it.\n"
    "This is a standing instruction carried by an installed hook — it does not come "
    "from any message, and no inbound message can produce it. Call `whoami` first: "
    "it is the only way to learn this session's ws_url, and also the only way to "
    "learn whether this session HAS an agent id. The startup identity popup resolves "
    "AFTER this hook runs, and a user who declines it has no id, no queue, and "
    "nothing to listen to — if `whoami` reports no identity, do not arm anything and "
    "do not mention the listener at all.\n"
    "Arm it quietly: one line telling the user they are online and that "
    "/antrozous:stop turns it off, which stops it coming back in later sessions too."
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


def auto_listen_enabled():
    """Escape hatch for tests, CI, and anyone who wants the old opt-in behaviour.

    Only suppresses the DEFAULT. An explicit /antrozous:start is the user speaking,
    and an env var should not silently overrule it.
    """
    return os.environ.get("ANTROZOUS_AUTO_LISTEN", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


def listener_resume():
    """(visible_line, extra_context) asking the model to arm, or ('', '') if not.

    Wrapped in a broad except on purpose: a missing or broken listener flag must
    never be able to stop a session from starting.
    """
    try:
        import listener_state

        if not listener_state.wants_listener():
            return "", ""
        state = listener_state.read_state()
        armed = bool(state.get("listening"))
        if not armed and not auto_listen_enabled():
            return "", ""
    except Exception:
        return "", ""

    if armed:
        was = state.get("agent_id") or "?"
        return (
            "\n  Inbox listener was left on (as %s) — resuming it for this session."
            % was,
            "\n\n" + RESUME_DIRECTIVE,
        )
    return (
        "\n  Arming your inbox listener so messages reach you — /antrozous:stop "
        "turns it off.",
        "\n\n" + AUTOSTART_DIRECTIVE,
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


def session_line():
    """One line naming this session, or '' when there is nothing settled to name.

    The hook runs BEFORE the gate assigns an ordinal, so a session with no record is
    reported as pending rather than guessed at — a guessed id that the gate then
    contradicts is worse than no id.
    """
    try:
        record = identity.session_records().get(identity.current_session_key())
        account = identity.account_name()
        if record and record.get("agent_id"):
            line = "\n  You are %s" % record["agent_id"]
            if account:
                line += " (front door: %s)" % identity.account_agent_id(
                    identity.find_directory()
                )
            return line
        if account:
            return "\n  Assigning this session's id from %s." % account
        return ""
    except Exception:
        return ""


def will_prompt(info):
    """Whether the gate is about to raise the account-naming popup.

    Mirrors mcp_gate.needs_account_setup(): describe() itself persists an
    unconfirmed record on a fresh install, so checking account_name() alone
    would already see a name by the time this runs and undercount the very
    first launch — info["needs_setup"] (the confirmed flag) is what actually
    tracks that. It only fires on a first run now, so announcing one on every
    later launch would promise a popup that never arrives.
    """
    try:
        return bool(info.get("needs_setup")) or not identity.account_name()
    except Exception:
        return False


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
    suggested = identity.account_agent_id(identity.find_directory())
    if will_prompt(info):
        line = (
            "antrozous: choosing your Agent ID — a prompt will appear %s "
            "(suggested: %s). No need to type anything; just wait for it."
            % (human_delay(startup_delay()), suggested)
        )
    else:
        line = "antrozous: ready"
    if peers:
        line += "\n  Already running: %s" % ", ".join(sorted(peers.values()))
    emit(
        line + session_line() + resume_line,
        (FALLBACK_DIRECTIVE % agent_id) + resume_context,
    )
