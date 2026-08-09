"""
FastAPI server to store and relay messages (the relay).

HTTP (pull):
  POST /send                     store a message (fires a doorbell to live recipients)
  GET  /inbox/{agent_id}         list pending (non-destructive)
  POST /inbox/{agent_id}/consume clear handled messages

WebSocket (push):
  WS   /ws/{agent_id}            a recipient connects and receives a content-free
                                 DOORBELL whenever a message lands for it. The
                                 doorbell carries NO body and NO attacker-controlled
                                 strings — only a trigger + a pending count — so a
                                 client (Monitor / channel) can react and then pull
                                 the real content through the approval gate.

Attachments (images/PDFs) are NOT carried inline in a message. The bytes rest in
a content-addressed blob store on the relay (blobs/<sha256>), and the message
carries only a small reference (Attachment: {sha256, mime, size}). Senders PUT
the bytes first, then /send the envelope with the ref; recipients fetch the blob
lazily (and only after user approval, in the gate).

Blob HTTP:
  PUT  /blob                     stream bytes in; cap-enforced + type-sniffed;
                                 returns {sha256, size, mime}
  GET  /blob/{sha256}            stream stored bytes back (opaque octet-stream)

In-memory store (MVP); the relay must stay running for a session. Persistence is
a follow-up (see RUNBOOK.md).
"""

import base64
import json
import os
import re
import hashlib
import tempfile

from datetime import datetime
from typing import List, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import StreamingResponse

from .models import Message, KeyBundle

app = FastAPI(title="Agent Message Relay")

# agent_id -> list of message dicts (JSON-safe, timestamp as ISO string)
inboxes: Dict[str, List[dict]] = {}

# agent_id -> {"ed25519": b64, "x25519": b64, "first_seen": iso}
# Senders fetch a recipient's x25519 key from here to seal a message. The relay is
# NOT trusted to bind names to keys: an agent id ends in a digest of its own ed25519
# key, and publish checks that, so a substituted key produces a mismatched id.
agent_keys: Dict[str, dict] = {}

BACKUP_FILE = "messages.json"
if os.path.exists(BACKUP_FILE):
    with open(BACKUP_FILE) as f:
        inboxes = json.load(f)

# ---------- blob store (content-addressed attachments) ----------
# Bytes rest here as blobs/<sha256> with NO extension — opaque and inert. Nobody
# on the relay ever opens them; recipients fetch and (after approval) materialize.
BLOB_DIR = os.environ.get("BLOB_DIR", "blobs")

# Hard ceiling per attachment. Enforced mid-stream at PUT time so a hostile
# sender can never buffer a bomb into the relay's RAM or fill its disk.
MAX_BLOB_BYTES = int(os.environ.get("MAX_BLOB_BYTES", str(10 * 1024 * 1024)))  # 10 MB

CHUNK = 64 * 1024

# A blob id is exactly a sha256 hex digest. Validating the path param against
# this kills path-traversal (e.g. GET /blob/../../etc/passwd) at the door.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# "<name>.<fingerprint>", where fingerprint is 8 base32 chars of sha256(ed25519 pub).
_QUALIFIED_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}[a-z0-9]\.([a-z2-7]{8})$")
FINGERPRINT_CHARS = 8


def _fingerprint(ed25519_raw: bytes) -> str:
    return (
        base64.b32encode(hashlib.sha256(ed25519_raw).digest())
        .decode()
        .lower()[:FINGERPRINT_CHARS]
    )


def sniff_mime(head: bytes) -> Optional[str]:
    """Identify file type from leading magic bytes. Returns a validated mime, or
    None if the bytes don't match our allowlist. We trust THIS, never the client's
    declared type — the sender is untrusted. Needs >= 12 bytes to rule on WEBP."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    return None


class ConnectionManager:
    """Tracks live WebSocket recipients per agent and pushes doorbells to them."""

    def __init__(self):
        self.active: Dict[str, List[WebSocket]] = {}

    async def connect(self, agent_id: str, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(agent_id, []).append(ws)

    def disconnect(self, agent_id: str, ws: WebSocket):
        conns = self.active.get(agent_id)
        if conns and ws in conns:
            conns.remove(ws)

    async def doorbell(self, agent_id: str, payload: dict):
        dead = []
        for ws in list(self.active.get(agent_id, [])):
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(agent_id, ws)

    def count(self, agent_id: str) -> int:
        return len(self.active.get(agent_id, []))


manager = ConnectionManager()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "agents": list(inboxes.keys()),
        "keys": len(agent_keys),
        "ws_connections": {a: manager.count(a) for a in manager.active},
    }


@app.post("/keys/{agent_id}")
def publish_keys(agent_id: str, bundle: KeyBundle):
    """Publish an agent's public keys so senders can seal messages to it.

    The id must end in a digest of the ed25519 key being published, and we check
    that here. This is what keeps the relay out of the trust path: it cannot
    substitute its own key for someone else's, because the substituted key would
    not hash to the fingerprint already baked into the address.
    """
    match = _QUALIFIED_ID_RE.match(agent_id)
    if not match:
        raise HTTPException(
            status_code=400,
            detail="agent id must be '<name>.<fingerprint>' to publish keys",
        )
    try:
        ed_raw = base64.b64decode(bundle.ed25519.encode(), validate=True)
        x_raw = base64.b64decode(bundle.x25519.encode(), validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="keys must be base64")
    if len(ed_raw) != 32 or len(x_raw) != 32:
        raise HTTPException(status_code=400, detail="keys must be 32 bytes each")
    if _fingerprint(ed_raw) != match.group(1):
        raise HTTPException(
            status_code=400,
            detail="ed25519 key does not match the fingerprint in the agent id",
        )

    existing = agent_keys.get(agent_id)
    # Overwrite is safe: only the holder of this key can produce a matching id.
    agent_keys[agent_id] = {
        "ed25519": bundle.ed25519,
        "x25519": bundle.x25519,
        "first_seen": (existing or {}).get("first_seen") or datetime.now().isoformat(),
    }
    rotated = bool(existing) and existing["x25519"] != bundle.x25519
    return {"status": "published", "agent_id": agent_id, "rotated": rotated}


@app.get("/keys/{agent_id}")
def get_keys(agent_id: str):
    bundle = agent_keys.get(agent_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="no keys published for this agent")
    return bundle


@app.put("/blob")
async def put_blob(request: Request):
    """Stream an attachment into the content-addressed store.

    Guards, in order: (1) fast-reject on a declared Content-Length over cap;
    (2) enforce the real cap on the actual byte stream, aborting the instant it is
    crossed; (3) sniff+allowlist the file type from magic bytes. The sha256 and
    byte count are computed in the same single pass that enforces the cap.

    Returns {sha256, size, mime}. The caller puts exactly these into an Attachment.
    """
    # (1) Fast reject: the header is a hint, not enforcement — a liar can understate
    # it, which is why (2) below is the real guard. But an honest over-cap header
    # lets us 413 before reading a single byte.
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_BLOB_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="attachment exceeds %d bytes" % MAX_BLOB_BYTES,
                )
        except ValueError:
            pass  # malformed header — ignore, the stream counter still protects us

    os.makedirs(BLOB_DIR, exist_ok=True)
    h = hashlib.sha256()
    total = 0
    head = b""
    mime = None
    tmp = tempfile.NamedTemporaryFile(dir=BLOB_DIR, delete=False)
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            # (2) Real cap enforcement — running count on the true stream. Abort the
            # moment we cross, before writing the offending chunk's excess anywhere.
            total += len(chunk)
            if total > MAX_BLOB_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="attachment exceeds %d bytes" % MAX_BLOB_BYTES,
                )
            # (3) Type guard — accumulate a small header and sniff once we can.
            if mime is None:
                head += chunk
                if len(head) >= 12:
                    mime = sniff_mime(head)
                    if mime is None:
                        raise HTTPException(
                            status_code=415,
                            detail="unsupported or unrecognized file type",
                        )
            h.update(chunk)
            tmp.write(chunk)
        tmp.flush()
        tmp.close()

        if total == 0:
            raise HTTPException(status_code=400, detail="empty body")
        # Tiny file that never reached 12 bytes: sniff whatever we got.
        if mime is None:
            mime = sniff_mime(head)
            if mime is None:
                raise HTTPException(
                    status_code=415, detail="unsupported or unrecognized file type"
                )

        digest = h.hexdigest()
        final = os.path.join(BLOB_DIR, digest)
        if os.path.exists(final):
            os.unlink(tmp.name)  # dedup: identical bytes already stored
        else:
            os.replace(tmp.name, final)  # atomic within the same dir/filesystem
        return {"sha256": digest, "size": total, "mime": mime}
    except BaseException:
        # Any failure (cap/type reject, client disconnect, disk error) leaves no
        # partial blob behind.
        try:
            tmp.close()
            os.unlink(tmp.name)
        except OSError:
            pass
        raise


@app.get("/blob/{sha256}")
def get_blob(sha256: str):
    """Stream a stored blob back by its hash.

    Served as application/octet-stream with nosniff + attachment disposition on
    purpose: the store must NEVER advertise a renderable type. The recipient reads
    the validated mime from the message envelope, verifies the hash itself, and
    decides whether to materialize — the relay just hands over opaque bytes.
    """
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="invalid blob id")
    path = os.path.join(BLOB_DIR, sha256)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="blob not found")

    def gen():
        with open(path, "rb") as f:
            while True:
                b = f.read(CHUNK)
                if not b:
                    break
                yield b

    return StreamingResponse(
        gen(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="%s"' % sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.post("/send")
async def send_message(msg: Message):
    if msg.to_agent not in inboxes:
        inboxes[msg.to_agent] = []
    # mode="json" keeps the datetime as an ISO string so the store stays JSON-safe.
    inboxes[msg.to_agent].append(msg.model_dump(mode="json"))
    n = len(inboxes[msg.to_agent])
    # DOORBELL: a NEUTRAL, content-free signal — {type, pending} only. It must NOT
    # contain instructions: a receiver correctly treats channel content as untrusted
    # data (an embedded "call check_inbox" reads as prompt injection and is refused).
    # The doorbell's job is only to signal "something arrived"; the decision to call
    # check_inbox comes from a TRUSTED standing instruction (the user / a skill),
    # never from the frame itself.
    await manager.doorbell(msg.to_agent, {"type": "doorbell", "pending": n})
    return {"status": "sent", "pending": n}


@app.get("/inbox/{agent_id}")
def get_inbox(agent_id: str):
    # Non-destructive read: returns the pending messages without clearing them.
    return inboxes.get(agent_id, [])


@app.post("/inbox/{agent_id}/consume")
def consume_inbox(agent_id: str, count: int = -1):
    """Remove and return the oldest `count` messages (all if count<0).

    The receiver calls this AFTER it has handled a batch, so the same messages
    aren't shown again on the next check. Note (MVP): messages that arrive between
    a GET and this consume are not returned here — acceptable for the manual demo.
    """
    pending = inboxes.get(agent_id, [])
    n = len(pending) if count < 0 else min(count, len(pending))
    taken, inboxes[agent_id] = pending[:n], pending[n:]
    return {"consumed": taken, "remaining": len(inboxes[agent_id])}


@app.websocket("/ws/{agent_id}")
async def ws_inbox(websocket: WebSocket, agent_id: str):
    """A recipient holds this open to get doorbells. On connect it gets one
    'connected' frame carrying the current pending count (so a client that
    reconnects doesn't miss a backlog); thereafter one doorbell per new message."""
    await manager.connect(agent_id, websocket)
    try:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "connected",
                    "agent_id": agent_id,
                    "pending": len(inboxes.get(agent_id, [])),
                }
            )
        )
        while True:
            # Keep the socket open. We don't require client input; any received text
            # (e.g. a keepalive ping) is simply ignored.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(agent_id, websocket)
    except Exception:
        manager.disconnect(agent_id, websocket)
