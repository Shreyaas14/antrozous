# antrozous — addressing

Status: proposal.
Decision requested: approve the routing rule before code lands.

## 1. The problem

An address today is `<name>.<fingerprint>` — `ssh-reyaas.kbjz3w4a`. The fingerprint
identifies the device's key. The name identifies... something between a person and a
browser tab, depending on when you ask.

Concretely, `ssh-reyaas.kbjz3w4a` is simultaneously:

- the address you give people
- the name of one particular Claude Code session
- whatever `identity.json` happens to have saved as the default

Nothing structurally distinguishes it from `scratch.kbjz3w4a`. It is the account
address because a file says so, and that file changes when you rename.

Three failures fell out of this in one evening:

1. **Sends advertised the wrong reply-to.** `from_agent` was the account address
   while a session polled its own id, so replying reached a real inbox that nobody
   read. Eleven messages accumulated before anyone noticed, with no error anywhere.
2. **Renaming orphaned mail.** Inboxes are keyed by full id, so changing your name
   left the old inbox live and unpolled. Senders got no error — the old address
   still resolved and still had valid keys.
3. **Renaming was ambiguous.** Typing a name at launch might mean "name this tab" or
   "this is who I am", and the code had to guess.

All three are the same root cause: **identity and session are the same string.**

## 2. The model

Separate them.

```
kbjz3w4a                    the DEVICE. Derived from the keypair. This is identity.
  ├─ scratch.kbjz3w4a       a session. A sub-address, addressable directly.
  └─ review.kbjz3w4a        another.
```

The keypair in `~/.antrozous/key.json` already *is* the device identity — every id
you have ever used ends in a digest of it, and auth already accepts any of them. The
change is to stop pretending one session name is special.

**There is no account address.** There is a device, which has a fingerprint and
optionally a claimed alias, and there are sessions, which have names.

## 3. Addressing

| `to_agent` | goes to |
|---|---|
| `kbjz3w4a` | the device inbox |
| `ssh-reyaas` (claimed alias) | the device inbox |
| `scratch.kbjz3w4a` — registered session | that session's inbox |
| `old-name.kbjz3w4a` — not registered | the device inbox |

That last row is the important one. A name the recipient is not currently using
falls back to the device inbox rather than creating a dead one. **Renaming stops
being able to strand mail at all** — not "recoverable via `/inboxes`", but
impossible by construction.

Sessions opt in to their own inbox by registering the id. No heartbeat, no liveness
tracking: registration is explicit, and unregistering (or never registering) means
mail routes to the device.

`GET /inboxes` stays. It is still how a client discovers the device inbox plus any
session inboxes with mail waiting.

## 4. Aliases point at the key

Today `/resolve/ssh-reyaas` returns `ssh-reyaas.kbjz3w4a` — an alias for one id, so
renaming that session leaves the alias aimed at a stale inbox.

An alias should name the **device**, and the device is its ed25519 key. Store the
key, not the fingerprint:

```
aliases["ssh-reyaas"] = "psglS89qrigvookyi158w8/uXvqh8+S3YZZPCkJdQoU="   # ed25519 pub

/resolve/ssh-reyaas → {"ed25519": "psgl…", "fingerprint": "kbjz3w4a"}
```

The fingerprint is returned for display and addressing, but it is *derived*, not
stored. That matters: the fingerprint is a truncated hash, so two keys can collide
there, and an alias table keyed on 40 bits puts that truncation in the trust path
for every lookup. Keyed on the full key it cannot collide at all, and the caller can
re-derive the fingerprint itself and check it against whatever address it was given.

So the name a person types is bound to a specific key, and nothing shorter.

First claim still wins. The gate still pins the mapping locally and treats a repoint
as a hard error — and the pin becomes stronger, since it pins a full key rather than
a digest.

What you tell someone is now just: *"I'm `ssh-reyaas`."* No hash, no key, no session
name. The fingerprint only appears if they want to verify it out of band, which is
the role it should have had all along.

## 5. What this does to the confusing parts

**Renaming.** The launch prompt names the session, always. There is no case where it
changes your identity, so the first-run special case disappears and `set_identity`
becomes "claim a different alias" rather than "move my address".

**The primary slot.** Device mail has one obvious home instead of being one
session's inbox that another session borrows. Whoever holds primary drains the
device inbox; sessions drain their own. The `claim_primary` machinery stays but
stops being load-bearing for correctness.

**Reply-to.** `from_agent` is the session id, as of the current code. Unchanged —
and now a reply to a session that has since unregistered lands in the device inbox
instead of nowhere.

## 6. Migration

Every address in circulation is `name.fingerprint`, and rule 4 in §3 handles them:
an unregistered name routes to the device. So existing addresses keep working, and
they quietly become device addresses once the session using that name is gone.

The order that avoids breakage:

1. Relay accepts bare fingerprints, and the alias table starts storing ed25519 keys
   instead of ids. Routing for `name.fingerprint` is unchanged at this step.
2. Relay adds session registration; unregistered `name.fingerprint` starts falling
   back to the device inbox.
3. Gate registers its session id on startup, publishes under the fingerprint, and
   claims aliases against the fingerprint.
4. `share_this` in `whoami` becomes the alias or bare fingerprint.

Steps 1–2 are relay-only and backward compatible. Step 3 is the client cutover.

## 7. Open questions

1. **What do people actually type?** A bare fingerprint (`kbjz3w4a`) is stable and
   unambiguous but unreadable. An alias is readable but land-grabbable. Probably
   both, with the alias preferred and the fingerprint always accepted.
2. **Does the device inbox need a name at all in the wire format,** or is
   `to_agent: "kbjz3w4a"` enough? A bare 8-char base32 string is currently not a
   legal agent id, so the parser has to learn it.
3. **Unregistering.** Does a session release its inbox on clean shutdown, and what
   happens to mail already in it? Simplest answer: mail stays, and `/inboxes` surfaces
   it for the primary session to drain.
4. **Durability.** Out of scope here, but the relay's in-memory store loses all
   pending mail on redeploy, which is currently a bigger practical risk than any
   addressing bug.
