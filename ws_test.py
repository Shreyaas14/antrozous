#!/usr/bin/env python3
"""
Local check of the relay's WebSocket doorbell:
  - connect to /ws/<agent>  -> expect a 'connected' frame
  - POST /send to that agent -> expect a content-free 'doorbell' frame on the ws
  - wait, send again on the SAME open connection -> expect another doorbell
    (basic relay-side persistence — the socket stays live across a quiet gap)

Proves the relay push mechanics. The real question of whether Claude's Monitor
holds a ws open past its inactivity window is the LIVE test on the public relay.
"""
import asyncio, json, urllib.request, websockets

AGENT = "ws-test-agent"
WS = "ws://127.0.0.1:8000/ws/%s" % AGENT
SEND = "http://127.0.0.1:8000/send"


def post_send(content):
    payload = {"from_agent": "tester", "from_user": "t", "to_agent": AGENT,
               "to_user": AGENT, "content": content, "timestamp": "2026-07-02T00:00:00"}
    req = urllib.request.Request(SEND, data=json.dumps(payload).encode(),
                                 method="POST", headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


async def main():
    # clear any prior state for this test agent
    try:
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8000/inbox/%s/consume?count=-1" % AGENT, method="POST"), timeout=5).read()
    except Exception:
        pass

    async with websockets.connect(WS) as ws:
        hello = json.loads(await ws.recv())
        assert hello["type"] == "connected", hello
        print("CONNECTED  -> got 'connected' frame (pending=%d)                    OK" % hello["pending"])

        await asyncio.to_thread(post_send, "hello 1")
        db = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert db["type"] == "doorbell", db
        # doorbell must NOT carry body or sender strings
        assert set(db.keys()) <= {"type", "pending"}, ("doorbell leaked fields: %s" % db)
        print("DOORBELL   -> /send pushed a content-free doorbell (pending=%d)       OK" % db["pending"])

        await asyncio.sleep(3)
        await asyncio.to_thread(post_send, "hello 2")
        db2 = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert db2["type"] == "doorbell" and db2["pending"] == 2, db2
        print("PERSIST    -> same socket still delivering after a quiet gap          OK")

    print("\nRelay websocket doorbell verified locally (push works, body-free).")


if __name__ == "__main__":
    asyncio.run(main())
