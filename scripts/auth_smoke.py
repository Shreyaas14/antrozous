"""End-to-end check that the real gate can still talk to an authenticated relay.

Unit tests sign with hand-rolled headers; this drives mcp_gate's own code path, so a
mismatch between the client and server canonical strings shows up here.

Run against a relay started with the repo's server module:
    ANTROZOUS_HOME=/tmp/x uvicorn src.antrozous.server:app --port 8099
    ANTROZOUS_HOME=/tmp/x RELAY_URL=http://127.0.0.1:8099 python3 scripts/auth_smoke.py
"""

import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ANTROZOUS_STARTUP_PROMPT", "0")

import identity  # noqa: E402
import mcp_gate  # noqa: E402

FAILURES = []


def check(label, ok, detail=""):
    print(("  ok   " if ok else "  FAIL ") + label + (" — " + detail if detail else ""))
    if not ok:
        FAILURES.append(label)


def main():
    fp = mcp_gate.ensure_keys()
    agent = identity.compose_agent_id("smoke", fp)
    print("agent:", agent, "\nrelay:", mcp_gate.RELAY_URL, "\n")

    mcp_gate.publish_keys(agent)
    bundle = mcp_gate.http("GET", "/keys/%s" % agent)
    check("keys published and readable", bool(bundle and bundle.get("x25519")))

    # A different session NAME on the same device must resolve the same bundle —
    # this is the bug that silently downgraded sends to plaintext.
    alias = identity.compose_agent_id("smoke-2", fp)
    alias_bundle = mcp_gate.http("GET", "/keys/%s" % alias)
    check(
        "another session name resolves the same key",
        alias_bundle and alias_bundle.get("x25519") == bundle["x25519"],
    )

    payload = {
        "v": 1,
        "from_agent": agent,
        "to_agent": agent,
        "to_user": "me",
        "from_user": "me",
        "content": "smoke",
        "timestamp": "2026-01-01T00:00:00",
    }
    mcp_gate.http("POST", "/send", payload, as_agent=agent)
    check("signed send accepted", True)

    pending = mcp_gate.http("GET", "/inbox/%s" % agent, as_agent=agent)
    check("signed read returns the message", len(pending or []) == 1)

    try:
        mcp_gate.http("GET", "/inbox/%s" % agent)
        check("unsigned read is rejected", False, "it succeeded")
    except urllib.error.HTTPError as e:
        check("unsigned read is rejected", e.code == 401, "HTTP %d" % e.code)

    ticket = mcp_gate._ws_ticket(agent)
    check("ws ticket minted", bool(ticket))
    url = mcp_gate._ws_url(agent)
    check("ws url carries the ticket", "ticket=" in url)

    path = "/inbox/%s/consume?count=1" % agent
    res = mcp_gate.http("POST", path, as_agent=agent)
    check("signed consume drains it", (res or {}).get("remaining") == 0)

    # --- alias layer: a bare name must expand, and must stay pinned ---
    canonical, why = mcp_gate.resolve_peer("smoke")
    check(
        "bare name resolves to the qualified id", canonical == agent, why or canonical
    )

    pinned = mcp_gate._read_peers().get("smoke")
    check("resolution is pinned locally", pinned == fp, repr(pinned))

    # Simulate the relay repointing the name at someone else's key.
    peers = mcp_gate._read_peers()
    peers["smoke"] = "aaaaaaaa"
    identity._write_json(mcp_gate._peers_path(), peers)
    hijacked, reason = mcp_gate.resolve_peer("smoke")
    check(
        "a repointed alias is a hard error",
        hijacked is None and "REPOINTED" in (reason or ""),
        (reason or "")[:60],
    )
    peers["smoke"] = fp
    identity._write_json(mcp_gate._peers_path(), peers)

    # --- rename must not strand mail ---
    old = agent
    mcp_gate.http(
        "POST",
        "/send",
        dict(payload, to_agent=old, content="pre-rename"),
        as_agent=agent,
    )
    renamed = identity.compose_agent_id("smoke-renamed", fp)
    # _adopt_session_id, not a bare assignment: inbox_addresses only sweeps the
    # other inboxes for the session holding the primary slot, and claiming that
    # slot requires a registered session record.
    mcp_gate._adopt_session_id(renamed)
    identity.set_agent_id(identity.global_dir(), renamed)
    mcp_gate._publish_identities()

    stranded = dict(mcp_gate.other_queues())
    check("the abandoned queue is reported", old in stranded, repr(stranded))

    polled = mcp_gate.inbox_addresses()
    check(
        "but this session still polls ONLY its own queue",
        polled == [renamed],
        repr(polled),
    )

    # Signed AS the abandoned id, which is legal because it ends in the same key
    # digest. Signing as the new id would (correctly) 401.
    left = mcp_gate.http("GET", "/inbox/%s" % old, as_agent=old) or []
    check("old inbox is still readable after renaming", len(left) >= 1)

    health = mcp_gate.http("GET", "/health")
    check(
        "health is not a directory",
        isinstance(health.get("agents"), int) and "ws_connections" not in health,
        repr(health),
    )

    print(
        "\n%s" % ("FAILED: " + ", ".join(FAILURES) if FAILURES else "all checks passed")
    )
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
