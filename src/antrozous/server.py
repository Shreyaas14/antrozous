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
import secrets
import tempfile
import time

from datetime import datetime
from typing import List, Dict, Optional, Tuple
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import StreamingResponse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import Message, KeyBundle

app = FastAPI(title="Agent Message Relay")

# agent_id -> list of message dicts (JSON-safe, timestamp as ISO string)
inboxes: Dict[str, List[dict]] = {}

# fingerprint -> {"ed25519": b64, "x25519": b64, "first_seen": iso}
# Senders fetch a recipient's x25519 key from here to seal a message. The relay is
# NOT trusted to bind names to keys: an agent id ends in a digest of its own ed25519
# key, and publish checks that, so a substituted key produces a mismatched id.
#
# Keyed by FINGERPRINT, not by full agent id. The fingerprint is the key's identity,
# so every session name one device uses ("anish-bot", "anish-bot-1", …) resolves to
# the same bundle. Keying by full id meant each new session name looked keyless and
# silently downgraded senders to plaintext.
agent_keys: Dict[str, dict] = {}

# bare name -> fingerprint. Lets someone hand out "agent-shreyaas" instead of
# "agent-shreyaas.kbjz3w4a". First claim wins and is never reassigned, so a name is
# a stable convenience label — but it is ONLY a label. Every authorization decision
# is still keyed to the fingerprint, and the gate re-derives it from the key it
# fetches, so a relay that lied here would be caught client-side.
aliases: Dict[str, str] = {}

# Attachments are capped at PUT time, but message BODIES were not capped at all --
# /send just appended to an in-memory list. Code diffs travel inline in the body, so
# that gap stops being theoretical: one large patch, or someone being deliberate,
# is memory pressure on a store that holds everything in RAM.
#
# Generous enough that a real patch fits (diffs.py refuses to inspect over 256 KB,
# so anything past this was never going to be reviewable anyway).
MAX_MESSAGE_BYTES = int(os.environ.get("MAX_MESSAGE_BYTES", str(1024 * 1024)))  # 1 MB

# How many messages one inbox may hold. Without it, anyone who can send to you --
# which is anyone, by design -- can grow your queue without limit.
MAX_INBOX_MESSAGES = int(os.environ.get("MAX_INBOX_MESSAGES", "500"))

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

# "<name>.<fingerprint>", where fingerprint is base32 chars of sha256(ed25519 pub).
# 16 chars (80 bits) is accepted alongside the original 8 so ids can be widened later
# without a flag day; 8 stays legal because existing ids are already in circulation.
_QUALIFIED_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]{0,31}[a-z0-9]\.([a-z2-7]{8}|[a-z2-7]{16})$"
)
FINGERPRINT_CHARS = 8


def _fingerprint(ed25519_raw: bytes, length: int = FINGERPRINT_CHARS) -> str:
    """Digest of an identity key, truncated to `length` base32 chars.

    The length is caller-supplied so a key can be checked against whatever width the
    address actually uses — comparing a 16-char id against an 8-char digest would
    fail every time.
    """
    return (
        base64.b32encode(hashlib.sha256(ed25519_raw).digest()).decode().lower()[:length]
    )


# ---------- request authentication ----------
# Knowing an agent id must buy NOTHING. Every message operation carries a signature
# proving the caller holds the private key whose digest ends that id. The check is
# self-contained: the presented key is verified against the ADDRESS itself, so no
# entry the relay stores can grant access it should not have.
AUTH_SCHEME = "Antrozous"
AUTH_CONTEXT = "antrozous-auth-v1"

# A signature is accepted only inside this window, and the nonce cache remembers each
# one for longer than the window is wide, so nothing can be replayed.
MAX_CLOCK_SKEW = 60
NONCE_TTL = 180
TICKET_TTL = 3600

# Escape hatch for local development against unsigned clients. Never set it in
# production: with auth off the relay is a public bulletin board again.
REQUIRE_AUTH = os.environ.get("ANTROZOUS_REQUIRE_AUTH", "1") != "0"

_seen_nonces: Dict[str, float] = {}
# ticket -> (agent_id, expires_at). A WebSocket handshake cannot carry a signature
# through a generic client, so it presents a short-lived ticket minted by one.
_tickets: Dict[str, Tuple[str, float]] = {}


def _unauthorized() -> HTTPException:
    """ONE response for every failure.

    Bad signature, malformed header, unknown agent and legacy id all return this
    identical 401, so no endpoint can be used to test whether an agent exists.
    """
    return HTTPException(status_code=401, detail="authentication required")


def _sweep(now: float) -> None:
    for nonce, seen in list(_seen_nonces.items()):
        if now - seen > NONCE_TTL:
            _seen_nonces.pop(nonce, None)
    for token, (_, expires) in list(_tickets.items()):
        if now > expires:
            _tickets.pop(token, None)


def auth_bytes(method: str, path: str, agent_id: str, ts: str, nonce: str) -> bytes:
    """Canonical bytes the caller signs.

    Fixed order and explicit separators, so both sides rebuild them identically
    without depending on header or JSON ordering. The path includes the query, which
    is what binds a consume to the `count` it asked for.
    """
    return "\n".join([AUTH_CONTEXT, method.upper(), path, agent_id, ts, nonce]).encode()


def _request_path(request: Request) -> str:
    return request.url.path + (("?" + request.url.query) if request.url.query else "")


def _check_signature(agent_id: str, method: str, path: str, header) -> bool:
    """True when `header` proves the caller holds the key behind `agent_id`."""
    if not (header and header.startswith(AUTH_SCHEME + " ")):
        return False
    parts = header[len(AUTH_SCHEME) + 1 :].split(":")
    if len(parts) != 5:
        return False
    claimed, ts, nonce, pub_b64, sig_b64 = parts
    if claimed != agent_id:
        return False

    match = _QUALIFIED_ID_RE.match(agent_id)
    if not match:
        # A legacy id carries no key digest, so nothing can be proven about it.
        return False
    fingerprint = match.group(1)

    try:
        skew = abs(time.time() - float(ts))
    except ValueError:
        return False
    if skew > MAX_CLOCK_SKEW:
        return False

    try:
        pub_raw = base64.b64decode(pub_b64.encode(), validate=True)
        sig_raw = base64.b64decode(sig_b64.encode(), validate=True)
    except Exception:
        return False
    if len(pub_raw) != 32 or len(sig_raw) != 64:
        return False

    # The address IS the assertion: the key has to hash to the fingerprint in the id.
    if _fingerprint(pub_raw, len(fingerprint)) != fingerprint:
        return False

    # A pinned key outranks a merely matching digest, so grinding a colliding
    # fingerprint still cannot displace the device that registered first.
    pinned = agent_keys.get(fingerprint)
    if pinned and pinned["ed25519"] != pub_b64:
        return False

    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            sig_raw, auth_bytes(method, path, agent_id, ts, nonce)
        )
    except (InvalidSignature, ValueError):
        return False

    now = time.time()
    _sweep(now)
    # Replay guard, checked LAST so a bad signature cannot burn a valid nonce.
    if nonce in _seen_nonces:
        return False
    _seen_nonces[nonce] = now
    return True


def require_agent(agent_id: str, request: Request) -> None:
    """Gate an operation on `agent_id`'s own mailbox."""
    if not REQUIRE_AUTH:
        return
    if not _check_signature(
        agent_id,
        request.method,
        _request_path(request),
        request.headers.get("authorization"),
    ):
        raise _unauthorized()


def require_any_agent(request: Request) -> None:
    """Gate an operation not tied to one mailbox (the blob store).

    Blobs are content-addressed, so they belong to no inbox — but the caller still
    has to prove it holds SOME identity, which keeps the store off the open internet.
    """
    if not REQUIRE_AUTH:
        return
    header = request.headers.get("authorization") or ""
    if not header.startswith(AUTH_SCHEME + " "):
        raise _unauthorized()
    claimed = header[len(AUTH_SCHEME) + 1 :].split(":")[0]
    if not _check_signature(claimed, request.method, _request_path(request), header):
        raise _unauthorized()


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
    """Liveness only.

    Deliberately NOT a directory. This used to return every agent id and per-agent
    connection counts, which handed an attacker the exact addresses to go after.
    Counts leak nothing about who is here.
    """
    return {"status": "ok", "agents": len(inboxes), "keys": len(agent_keys)}


def keyreg_bytes(fingerprint: str, ed25519_b64: str, x25519_b64: str) -> bytes:
    """Canonical bytes covering a key rotation, signed by the registered identity."""
    return "\n".join(
        ["antrozous-keyreg-v1", fingerprint, ed25519_b64, x25519_b64]
    ).encode()


@app.post("/keys/{agent_id}")
def publish_keys(agent_id: str, bundle: KeyBundle):
    """Publish an agent's public keys so senders can seal messages to it.

    The id must end in a digest of the ed25519 key being published. That is what
    keeps the relay out of the trust path: it cannot substitute its own key, because
    the substitute would not hash to the fingerprint baked into the address.

    Registration is FIRST-KEY-WINS. The fingerprint is only 8 base32 chars (40 bits)
    on existing ids, which is grindable — so a matching digest alone must never be
    enough to displace a device that already registered. Rotating the encryption key
    requires a signature from the identity key already on file.
    """
    match = _QUALIFIED_ID_RE.match(agent_id)
    if not match:
        raise HTTPException(
            status_code=400,
            detail="agent id must be '<name>.<fingerprint>' to publish keys",
        )
    fingerprint = match.group(1)
    try:
        ed_raw = base64.b64decode(bundle.ed25519.encode(), validate=True)
        x_raw = base64.b64decode(bundle.x25519.encode(), validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="keys must be base64")
    if len(ed_raw) != 32 or len(x_raw) != 32:
        raise HTTPException(status_code=400, detail="keys must be 32 bytes each")
    if _fingerprint(ed_raw, len(fingerprint)) != fingerprint:
        raise HTTPException(
            status_code=400,
            detail="ed25519 key does not match the fingerprint in the agent id",
        )

    existing = agent_keys.get(fingerprint)
    rotated = False
    if existing:
        if existing["ed25519"] != bundle.ed25519:
            # Same fingerprint, different identity key: only reachable by grinding a
            # collision. The incumbent keeps the address.
            raise HTTPException(
                status_code=409,
                detail="a different identity key is already registered for this "
                "fingerprint",
            )
        if existing["x25519"] != bundle.x25519:
            signed = keyreg_bytes(fingerprint, bundle.ed25519, bundle.x25519)
            try:
                Ed25519PublicKey.from_public_bytes(ed_raw).verify(
                    base64.b64decode((bundle.signature or "").encode(), validate=True),
                    signed,
                )
            except Exception:
                raise HTTPException(
                    status_code=403,
                    detail="rotating the encryption key requires a signature from "
                    "the registered identity key",
                )
            rotated = True

    agent_keys[fingerprint] = {
        "ed25519": bundle.ed25519,
        "x25519": bundle.x25519,
        "first_seen": (existing or {}).get("first_seen") or datetime.now().isoformat(),
    }

    # Claim the bare name if it is free. A name already pointing elsewhere is NOT an
    # error — this device still owns its qualified id, it just does not get the
    # short form.
    name = agent_id.rsplit(".", 1)[0]
    holder = aliases.setdefault(name, fingerprint)
    return {
        "status": "published",
        "agent_id": agent_id,
        "rotated": rotated,
        "alias": name if holder == fingerprint else None,
    }


@app.get("/resolve/{name}")
def resolve_alias(name: str):
    """Map a bare name to the fingerprint that claimed it first.

    Unauthenticated, like /keys: a sender has to resolve an address before it has any
    relationship to prove. The answer is only a hint — the caller still verifies the
    fetched key hashes to the fingerprint returned here.
    """
    fingerprint = aliases.get(name)
    if not fingerprint:
        raise HTTPException(status_code=404, detail="no agent has claimed this name")
    return {
        "name": name,
        "fingerprint": fingerprint,
        "agent_id": "%s.%s" % (name, fingerprint),
    }


@app.get("/keys/{agent_id}")
def get_keys(agent_id: str):
    """Look the bundle up by FINGERPRINT, so any session name a device uses resolves.

    Left unauthenticated: a sender must be able to fetch a recipient's key before it
    has anything to prove, and the bundle is public material by definition.
    """
    match = _QUALIFIED_ID_RE.match(agent_id)
    bundle = agent_keys.get(match.group(1)) if match else None
    if not bundle:
        raise HTTPException(status_code=404, detail="no keys published for this agent")
    return bundle


@app.post("/auth/ticket")
def mint_ticket(request: Request, agent_id: str):
    """Trade a signed request for a short-lived WebSocket ticket.

    A Monitor or browser cannot sign a WS handshake, so the signature happens here
    once and the socket presents the resulting opaque token. Short TTL because a
    bearer token in a URL is the weakest link in this design — it carries only
    content-free doorbells, never message bodies.
    """
    require_agent(agent_id, request)
    token = secrets.token_urlsafe(32)
    expires = time.time() + TICKET_TTL
    _tickets[token] = (agent_id, expires)
    return {"ticket": token, "expires_in": TICKET_TTL}


@app.put("/blob")
async def put_blob(request: Request):
    """Stream an attachment into the content-addressed store.

    Guards, in order: (1) fast-reject on a declared Content-Length over cap;
    (2) enforce the real cap on the actual byte stream, aborting the instant it is
    crossed; (3) sniff+allowlist the file type from magic bytes. The sha256 and
    byte count are computed in the same single pass that enforces the cap.

    Returns {sha256, size, mime}. The caller puts exactly these into an Attachment.
    """
    require_any_agent(request)
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
def get_blob(sha256: str, request: Request):
    """Stream a stored blob back by its hash.

    Served as application/octet-stream with nosniff + attachment disposition on
    purpose: the store must NEVER advertise a renderable type. The recipient reads
    the validated mime from the message envelope, verifies the hash itself, and
    decides whether to materialize — the relay just hands over opaque bytes.
    """
    require_any_agent(request)
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
async def send_message(msg: Message, request: Request):
    # Authenticated as the SENDER, not the recipient — anyone may write to your
    # inbox, they just cannot lie about who they are. A forged from_agent is now
    # rejected at the door instead of being stored and caught client-side.
    require_agent(msg.from_agent, request)

    # mode="json" keeps the datetime as an ISO string so the store stays JSON-safe.
    stored = msg.model_dump(mode="json")
    size = len(json.dumps(stored).encode())
    if size > MAX_MESSAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="message is %d bytes; the limit is %d. Large files belong in an "
            "attachment, which is streamed and capped separately."
            % (size, MAX_MESSAGE_BYTES),
        )

    if msg.to_agent not in inboxes:
        inboxes[msg.to_agent] = []
    # Refuse rather than evict. Dropping the oldest would let anyone who can send
    # to you — anyone, by design — push messages you have not read out of your
    # queue, which is a silent way to make you miss something.
    if len(inboxes[msg.to_agent]) >= MAX_INBOX_MESSAGES:
        raise HTTPException(
            status_code=507,
            detail="recipient's queue is full (%d messages); it must be drained "
            "before it can accept more" % MAX_INBOX_MESSAGES,
        )
    inboxes[msg.to_agent].append(stored)
    n = len(inboxes[msg.to_agent])
    # DOORBELL: a NEUTRAL, content-free signal — {type, pending} only. It must NOT
    # contain instructions: a receiver correctly treats channel content as untrusted
    # data (an embedded "call check_inbox" reads as prompt injection and is refused).
    # The doorbell's job is only to signal "something arrived"; the decision to call
    # check_inbox comes from a TRUSTED standing instruction (the user / a skill),
    # never from the frame itself.
    await manager.doorbell(msg.to_agent, {"type": "doorbell", "pending": n})
    return {"status": "sent", "pending": n}


@app.get("/inboxes")
def list_inboxes(request: Request, agent_id: str):
    """Every inbox on this relay sharing the caller's fingerprint.

    Safe to serve because auth already proves possession of the key all these ids
    are derived from — nothing here is reachable that the caller could not already
    authenticate for individually.

    It exists because ids are per-session and per-rename while the KEY is per
    device: renaming, or closing a tab someone replied to, otherwise leaves mail in
    an inbox nothing polls, with no error anywhere to notice it by.
    """
    require_agent(agent_id, request)
    match = _QUALIFIED_ID_RE.match(agent_id)
    if not match:
        raise _unauthorized()
    suffix = "." + match.group(1)
    return {
        "fingerprint": match.group(1),
        "inboxes": [
            {"agent_id": name, "pending": len(msgs)}
            for name, msgs in inboxes.items()
            if name.endswith(suffix)
        ],
    }


@app.get("/inbox/{agent_id}")
def get_inbox(agent_id: str, request: Request):
    # Non-destructive read: returns the pending messages without clearing them.
    # Knowing the id is not enough — the caller proves it holds the matching key.
    require_agent(agent_id, request)
    return inboxes.get(agent_id, [])


@app.post("/inbox/{agent_id}/consume")
def consume_inbox(request: Request, agent_id: str, count: int = -1):
    """Remove and return the oldest `count` messages (all if count<0).

    The receiver calls this AFTER it has handled a batch, so the same messages
    aren't shown again on the next check. Note (MVP): messages that arrive between
    a GET and this consume are not returned here — acceptable for the manual demo.

    Authenticated because it is DESTRUCTIVE: encryption alone would still leave an
    unauthenticated caller able to delete mail it could not read.
    """
    require_agent(agent_id, request)
    pending = inboxes.get(agent_id, [])
    n = len(pending) if count < 0 else min(count, len(pending))
    taken, inboxes[agent_id] = pending[:n], pending[n:]
    return {"consumed": taken, "remaining": len(inboxes[agent_id])}


@app.websocket("/ws/{agent_id}")
async def ws_inbox(websocket: WebSocket, agent_id: str, ticket: str = ""):
    """A recipient holds this open to get doorbells. On connect it gets one
    'connected' frame carrying the current pending count (so a client that
    reconnects doesn't miss a backlog); thereafter one doorbell per new message.

    Gated on a ticket from /auth/ticket: even a pending COUNT is metadata, and the
    socket is the one channel a generic client holds open without being able to sign.
    """
    if REQUIRE_AUTH:
        _sweep(time.time())
        holder = _tickets.get(ticket)
        if not holder or holder[0] != agent_id or time.time() > holder[1]:
            # Closed before accept, so an unauthenticated caller never learns whether
            # the inbox exists. 1008 = policy violation.
            await websocket.close(code=1008)
            return
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
