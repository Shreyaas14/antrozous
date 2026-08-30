# antrozous — message encryption design

Status: HISTORICAL. Written as a proposal before encryption shipped; encryption
has since landed, so "not implemented" and the "decision requested" below are both
out of date. Section 1 in particular describes the PRE-encryption state -- "today a
message is plaintext from end to end" was true when this was written and is not
true now. The body has deliberately not been rewritten: doing that faithfully needs
an audit of the crypto implementation as shipped, which no one has done, and a
half-corrected security document is worse than one that says plainly which era it
belongs to. Treat the sections below as the design intent, and the code as the
authority on what was actually built.

Decision requested (at the time): approve scheme + phasing before code lands.

## 1. Where we are

Today a message is plaintext from end to end:

- `mcp_gate.py` POSTs `{from_agent, from_user, to_agent, to_user, content, timestamp, attachments}` to the relay.
- `server.py` holds it in the `inboxes` dict **in memory only**; the
  `messages.json` mirror named in `BACKUP_FILE` is read at startup and never
  written, so a redeploy drops every queue.
- Attachments rest as plaintext bytes in `blobs/<sha256>`.
- The relay runs on Railway, so the operator (and anyone who compromises that host, or reads that disk) sees every message body and every attachment.

Two holes matter as much as the missing crypto, and any encryption design has to
address them or it is decoration:

**No read authorization.** `GET /inbox/{agent_id}` returns any agent's pending
messages to any caller. Encryption would stop the reader understanding the
bodies, but they would still drain the queue via `POST /inbox/{id}/consume` and
see who is talking to whom.

**No sender authentication.** `from_agent` is a string the sender picks. Anyone
can claim to be `agent-9210a9a2e7`. The approval gate shows that string to the
user as `From:`, so a spoofed sender directly attacks the human's decision — the
one place antrozous asks a person to exercise judgment.

An agent id is currently `agent-` + 5 random bytes with no key material bound to
it. It is a *handle*, not an *identity*. The work below is largely about turning
it into one.

## 2. Threat model

Adversaries we intend to stop:

| # | Adversary | Capability | Addressed by |
|---|---|---|---|
| T1 | Relay operator / host compromise | Reads all stored state at rest | E2E encryption |
| T2 | Network observer | Sees traffic to the relay | TLS (already) + E2EE |
| T3 | Impersonator | Sends as someone else | Ed25519 signatures |
| T4 | Inbox thief | Reads/drains another agent's inbox | Signed-request relay auth |
| T5 | Tamperer | Rewrites a stored message before delivery | AEAD + signature |

Explicitly out of scope:

- **Metadata.** The relay must know `to_agent` to route, and it sees timing,
  message sizes, and the social graph. Hiding that needs sealed-sender or mixnet
  machinery that is far beyond this project's value.
- **Malicious recipient.** Anyone you send to can leak the plaintext. Not a crypto
  problem.
- **Compromised endpoint.** If an agent's machine is owned, its keys are owned.
  Section 5 limits the blast radius but cannot eliminate it.
- **Prompt injection in message content.** Already handled, and handled well, by
  the approval gate. Encryption is orthogonal to it — see §7.

## 3. Why not Double Ratchet

Double Ratchet is the right answer to a question antrozous isn't asking. Four
concrete mismatches:

**Its security comes from replies; antrozous messages are one-shot.** The DH
ratchet advances when the conversation turns around. Forward secrecy and
post-compromise healing accrue per round trip. Antrozous traffic is dominated by
fire-and-forget sends — agent A tells agent B one thing, often the only thing it
will ever send. A ratchet that never receives a reply never steps, so you get
exactly the security of a single sealed box while paying for per-peer session
state, a prekey server, and a skipped-message-key cache.

**Its state model fights ours.** DR requires durable, correctly persisted,
never-rolled-back session state for every peer, on both sides. Antrozous identity
is `.antrozous/identity.json` in a project directory, and agents are Claude Code
sessions that are created and destroyed constantly. Today, losing that file costs
you a name — you mint a new one and carry on. Under DR, losing it makes every
pending and archived message from every peer permanently undecryptable, and a
restored-from-backup directory silently desyncs the ratchet into the same state.
Fragility scales with the number of peers.

**Long offline windows hit its worst-tested path.** Recipients here can be
offline for days while messages queue. That means heavy reliance on out-of-order
and skipped-message handling — precisely the part that is subtle, and precisely
where the Python implementations are least battle-tested.

**Library risk points the wrong way.** PyNaCl and `cryptography` are audited
libsodium/OpenSSL bindings maintained by people who do this full time. The Python
Double Ratchet implementations are single-maintainer hobby projects. Adopting DR
via one of them is *more* cryptographic risk than a sealed box, not less — the
opposite of why you would reach for a famous protocol.

This is not a dead end. DR's prerequisite is exactly the long-term identity
keypair that §4 introduces, so if a long-lived, chatty A↔B pair later justifies
real forward secrecy, it can be layered on as an opt-in session upgrade without
redoing anything below.

## 4. Proposed scheme

Boring, well-trodden primitives, all from libsodium via PyNaCl:

```
identity  : Ed25519 keypair          (signing, long-lived, IS the agent id)
encryption: X25519 keypair           (derived from the Ed25519 key)
per message:
  ephemeral X25519 keypair -> ECDH -> HKDF -> XChaCha20-Poly1305
  = crypto_box_seal (libsodium sealed box)
signature : Ed25519 detached, over the ciphertext (sign-then-encrypt's safe cousin)
```

### 4.1 The agent id becomes a key fingerprint

Instead of `agent-` + random hex, an id is derived from the public key:

```
agent_id = "agent-" + base32(sha256(ed25519_pubkey))[:12].lower()
```

This makes ids self-authenticating: given a claimed id and a public key, anyone
can check they match, with no directory lookup. It also makes the relay's key
directory (§4.3) far less dangerous, because the relay cannot substitute a key
without producing an id that fails to match.

Existing random ids keep working — see §6.

### 4.2 Wire format

`Message` gains a version and swaps the plaintext body for a sealed one:

```python
class SealedMessage(BaseModel):
    v: int = 2
    from_agent: str
    to_agent: str
    timestamp: datetime
    ciphertext: str          # base64, sealed box over the inner plaintext
    signature: str           # base64, Ed25519 over (v||from||to||ts||ciphertext)
    sender_pubkey: str       # base64, Ed25519; must hash to from_agent
```

The inner plaintext, which only the recipient ever sees, carries the fields the
relay currently reads:

```json
{ "from_user": "...", "to_user": "...", "content": "...",
  "attachments": [{ "sha256": "...", "mime": "...", "size": 0, "key": "..." }] }
```

Note `from_user`/`to_user`/`content` move *inside* the envelope. The relay keeps
only what it needs to route: `to_agent`, plus `from_agent` and the timestamp for
display and rate limiting.

**Verify before decrypt.** The recipient checks `sha256(sender_pubkey)` matches
`from_agent`, then verifies the signature over the ciphertext, and only then
opens the sealed box. Rejecting bad signatures before touching the AEAD keeps
unauthenticated attacker-chosen bytes away from the decryption path.

### 4.3 Key distribution

The relay hosts a key directory:

```
POST /keys/{agent_id}   register {pubkey, sig}  — TOFU, first claim wins
GET  /keys/{agent_id}   -> {pubkey, first_seen}
```

The relay is untrusted, so it could serve a wrong key. Three things make that
survivable, in increasing order of strength:

1. **Self-authenticating ids (§4.1).** A substituted key produces a mismatched
   id, which the gate rejects outright. This alone defeats a passive substitution.
2. **Pin on first use.** The gate records each peer's key in
   `.antrozous/peers.json`. A *changed* key for a known peer is a hard error
   surfaced to the user, never a silent re-trust.
3. **Fingerprint verification.** `whoami` prints a short fingerprint; the approval
   prompt shows the sender's. Two humans comparing them over any other channel
   closes the gap completely.

TOFU registration means the first agent to claim an id binds its key to it. With
key-derived ids that is not a land grab — you can only claim the id matching a
key you hold.

### 4.4 Attachments

Blobs get encrypted client-side before upload:

```
key = random(32)
ciphertext = XChaCha20-Poly1305(key, plaintext_bytes)
PUT /blob  <- ciphertext
ref = { sha256: sha256(ciphertext), mime, size, key }   # key travels sealed inside the envelope
```

Two consequences to accept deliberately:

- **`sniff_mime` in `server.py` stops working.** The relay cannot inspect
  ciphertext, so the magic-byte allowlist has to move client-side, into the
  gate, before encryption. The size cap still works server-side and is unchanged.
  This is a real loss: the relay currently rejects hostile file types centrally
  for everyone, and afterward each client enforces it for itself.
- **Cross-recipient dedup dies.** Content-addressing over ciphertext means the
  same file sent twice stores twice. Fine at this scale.

### 4.5 Relay authorization (fixes T4)

Inbox reads and consumes require proof of key possession:

```
Authorization: Antrozous <agent_id>:<base64 ed25519 sig over "METHOD\npath\ntimestamp\nnonce">
```

Relay verifies against the registered pubkey, rejects timestamps outside ±60s,
and keeps a short-lived nonce cache to stop replay. This is worth doing whether
or not the encryption work proceeds — it is the difference between "inboxes are
private" and "inboxes are a public bulletin board."

## 5. What this does and does not buy

**Forward secrecy, partially.** Sealed boxes use a fresh ephemeral keypair per
message, discarded after send. Compromising a *sender* later reveals nothing
about what it sent. Compromising a *recipient* does expose past messages that are
still in existence, because the recipient's static key opens all of them.

If recipient-side forward secrecy matters, the cheap 80% is **key rotation**:
publish a new encryption key every N days, keep the previous one only long enough
to drain the inbox, and delete it. No per-peer state, nothing to desync, no
protocol change — and it is where I would go before reaching for a ratchet.

**Still visible to the relay:** who messages whom, when, how often, and roughly
how large. Stated plainly because it is the honest limit of this design.

## 6. Migration

`v` in the envelope lets both formats coexist:

1. Relay accepts v1 and v2. Gate sends v1 unless the recipient has a registered
   key. Nothing breaks.
2. Gate registers a key on first run and starts preferring v2 per-recipient.
   Legacy random-hex ids keep working — they just bind a key by TOFU rather than
   deriving from one, so they get §4.3 protections 2 and 3 but not 1.
3. Once both sides are keyed, flip a config flag to refuse v1 and warn on the
   downgrade.

The v1 path must be removable on a flag rather than by negotiation, or an
attacker who can drop packets forces a downgrade to plaintext.

## 7. Interaction with the approval gate

Decryption happens **in the gate, before the elicitation prompt**. The user
reviews plaintext exactly as today. E2EE does not weaken the isolation property:
content is decrypted locally, shown for review, and enters the model's context
only on Accept.

It strengthens the gate in one specific way. The `From:` line in the approval
prompt is currently an unverified string — the human is asked to make a trust
decision partly on the basis of a field the sender forged for free. After §4.2
that line is cryptographically bound to a key, and the prompt can say so.

## 8. Dependencies

Add PyNaCl to the gate. Launch changes from:

```json
"command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/mcp_gate.py"]
```

to:

```json
"command": "uv",
"args": ["run", "--with", "pynacl", "--python", "3.10",
         "${CLAUDE_PLUGIN_ROOT}/mcp_gate.py"]
```

uv caches the resolved environment, so this stays effectively zero-install after
the first run and preserves the "no venv coupling" goal. The failure mode it
introduces is real and needs handling: uv missing from PATH, or no network on
first run. The gate should detect both and fail with an actionable message rather
than a stack trace.

`cryptography>=48.0.0` is already a project dependency, and it can supply every
primitive here if you would rather not add PyNaCl — its API is clumsier
(sealed boxes are hand-assembled from X25519 + HKDF + ChaCha20Poly1305) but it is
one less dependency.

## 9. Phasing

Ordered so each phase is independently useful and shippable:

| Phase | Work | Buys |
|---|---|---|
| 1 | Ed25519 keygen, key-derived ids, key directory, signed sends, verify-on-receive | T3, T5 — no more impersonation |
| 2 | Signed-request auth on inbox read/consume | T4 — inboxes stop being public |
| 3 | Sealed-box bodies, v2 envelope, gate-side mime allowlist | T1, T2 — relay goes blind |
| 4 | Encrypted blobs | T1 for attachments |
| 5 | Recipient key rotation | Recipient-side forward secrecy |

Phase 2 is the highest value-per-line in the list and does not depend on phase 3.
If only one thing gets built, build phases 1–2.

## 10. Open questions

1. **Key loss = identity loss.** If `.antrozous/identity.json` is deleted, the
   agent's id changes and queued messages become undecryptable. Acceptable, or do
   we need an export/backup flow?
2. **Multi-machine agents.** Same logical agent on two machines currently means
   two ids. Under key-derived ids that becomes explicit. Share the private key,
   or treat them as distinct agents?
3. **Does the relay retain plaintext v1 during migration,** or do we hard-cut?
4. **Group messages** are not addressed here. Sealed boxes are per recipient, so
   an N-recipient message means N encryptions. Fine for small N; worth knowing
   before someone designs a broadcast feature on top.
