#!/usr/bin/env python3
"""
Offline E2E self-test: drives mcp_gate.py over pipes (playing the Claude client)
against a LIVE relay, exercising send_message + check_inbox + the elicitation gate.

Proves before any manual step:
  - send_message reaches the relay
  - check_inbox shows each message and returns ONLY approved content
  - declined/cancelled messages never appear in the model-visible result

Requires the relay running at RELAY_URL (default http://127.0.0.1:8000).
"""
import subprocess, json, os, sys, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(ROOT, "mcp_gate.py")
RELAY = os.environ.get("RELAY_URL", "http://127.0.0.1:8000").rstrip("/")
BODY = "SELFTEST-BODY-PHRASE-XYZ"


def relay_up():
    try:
        urllib.request.urlopen(RELAY + "/health", timeout=3).read()
        return True
    except Exception:
        return False


class Gate:
    def __init__(self, agent_id):
        env = dict(os.environ, AGENT_ID=agent_id, USER_ID="tester", RELAY_URL=RELAY)
        self.p = subprocess.Popen(["python3", GATE], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, env=env)

    def send(self, o):
        self.p.stdin.write(json.dumps(o) + "\n"); self.p.stdin.flush()

    def recv(self):
        line = self.p.stdout.readline()
        return json.loads(line) if line else None

    def handshake(self, elicit=True):
        caps = {"elicitation": {}} if elicit else {}
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-11-25", "capabilities": caps,
                              "clientInfo": {"name": "selftest", "version": "0"}}})
        assert self.recv()["result"]["serverInfo"]["name"] == "antrozous-gate"
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, name, args, _id):
        self.send({"jsonrpc": "2.0", "id": _id, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
        return self.recv()

    def call_with_elicits(self, name, args, _id, actions):
        """Call a tool, answering each elicitation with the next action in `actions`."""
        self.send({"jsonrpc": "2.0", "id": _id, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
        it = iter(actions)
        while True:
            m = self.recv()
            if m.get("method") == "elicitation/create":
                self.send({"jsonrpc": "2.0", "id": m["id"],
                           "result": {"action": next(it), "content": {}}})
            elif m.get("id") == _id:
                return m

    def close(self):
        try: self.p.stdin.close()
        except Exception: pass
        self.p.wait(timeout=5)


def text(resp):
    return resp["result"]["content"][0]["text"]


if not relay_up():
    print("RELAY NOT RUNNING at %s — start it first (see RUNBOOK.md)." % RELAY)
    sys.exit(2)

# clear agent-B
urllib.request.urlopen(urllib.request.Request(RELAY + "/inbox/agent-B/consume?count=-1",
                                              method="POST"), timeout=5).read()

# 1) SEND via the MCP tool (agent-A -> agent-B)
a = Gate("agent-A"); a.handshake()
r = a.call("send_message", {"to_agent": "agent-B", "content": "%s: hello from A" % BODY}, 2)
assert "Sent to agent-B" in text(r), text(r)
a.close()
print("SEND      -> message reached relay                                     OK")

# 2) CHECK + DECLINE  (content must NOT come back)
b = Gate("agent-B"); b.handshake()
r = b.call_with_elicits("check_inbox", {}, 3, ["decline"])
assert BODY not in text(r), ("LEAK on decline: %s" % text(r))
assert "APPROVED none" in text(r) or "APPROVED 0" in text(r)
b.close()
print("DECLINE   -> no message body in model-visible result                   OK")

# 3) SEND again, then CHECK + ACCEPT  (content SHOULD come back, wrapped)
a = Gate("agent-A"); a.handshake()
a.call("send_message", {"to_agent": "agent-B", "content": "%s: please review" % BODY}, 2)
a.close()
b = Gate("agent-B"); b.handshake()
r = b.call_with_elicits("check_inbox", {}, 4, ["accept"])
assert BODY in text(r) and "external_message" in text(r), ("accept should return wrapped: %s" % text(r))
b.close()
print("ACCEPT    -> approved message returned as untrusted data               OK")

# 4) CHECK empty (consume worked — nothing re-prompted)
b = Gate("agent-B"); b.handshake()
r = b.call("check_inbox", {}, 5)
assert "empty" in text(r).lower(), ("inbox should be empty after consume: %s" % text(r))
b.close()
print("CONSUME   -> inbox empty after handling (no re-prompt)                  OK")

print("\nEnd-to-end gate logic verified against the live relay.")
print("Next: the MANUAL test — receive in a second terminal (see RUNBOOK.md).")
