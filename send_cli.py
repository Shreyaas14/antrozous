#!/usr/bin/env python3
"""
Tiny stdlib sender — lets THIS terminal push a message to the relay without a
full Claude session. Mirrors what the send_message MCP tool does.

  usage: python3 send_cli.py <to_agent> <content> [--from-agent A] [--from-user U]
                             [--to-user U] [--relay URL]
"""
import sys, os, json, argparse, datetime, urllib.request, urllib.error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("to_agent")
    ap.add_argument("content")
    ap.add_argument("--from-agent", default=os.environ.get("AGENT_ID", "agent-A"))
    ap.add_argument("--from-user", default=os.environ.get("USER_ID") or os.environ.get("USER") or "alice")
    ap.add_argument("--to-user", default=None)
    ap.add_argument("--relay", default=os.environ.get("RELAY_URL", "http://127.0.0.1:8000").rstrip("/"))
    a = ap.parse_args()

    payload = {"from_agent": a.from_agent, "from_user": a.from_user,
               "to_agent": a.to_agent, "to_user": a.to_user or a.to_agent,
               "content": a.content, "timestamp": datetime.datetime.now().isoformat()}
    req = urllib.request.Request(a.relay + "/send", data=json.dumps(payload).encode(),
                                 method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print("relay:", r.read().decode())
        print("sent %r -> %s" % (a.content, a.to_agent))
    except urllib.error.URLError as e:
        print("ERROR: could not reach relay at %s (%s)" % (a.relay, e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
