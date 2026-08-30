# antrozous — identity and session addressing design

Status: implemented, 2026-08-30.

## 1. Where we are

An antrozous id is `<name>.<fingerprint>`, where the fingerprint is 8 base32 chars
of the sha256 of the device's ed25519 public key. Every id on one device shares one
fingerprint, and the relay keys its key directory by fingerprint rather than by full
id, so all of a device's names resolve to one key bundle.

On top of that sit three overlapping concepts and four resolution tiers:

| Concept | Built by | Lifetime | Meant for |
|---|---|---|---|
| Fingerprint | `keys` digest, cached in `identity.json` | device | binding a name to a key |
| Account id | `identity.account_agent_id()` | forever | "the address you hand out" |
| Session id | startup popup → `SESSION_AGENT_ID` | one process | the queue a session polls |
| Project override | `.antrozous/identity.json` | per directory | a directory that is its own agent |

Resolution is `$AGENT_ID` → project file → global file → generate
(`identity.resolve_agent_id`).

The first run names *you*: `_handle_startup_reply` writes the saved default only
when `info["needs_setup"]`. Every run after that names *the tab only*. So from
session two onward the session id and the account id diverge by design, and
`whoami` carries four id fields plus four mutually exclusive `note` branches to
explain which name is the real one.

This is the confusion the redesign exists to remove. Evidence that it is not merely
theoretical: the account id on the author's own machine is `anish-bot-1.e5ox72jb`,
renamed from `agent-anishrane`. The trailing `-1` is a session ordinal that was
typed into the per-session popup and became the permanent address.

## 2. What the code actually does

Four places where the documented behaviour and the implemented behaviour disagree.
Each is load-bearing for the design below.

**F1 — outbound mail is sent as the SESSION id, not the account id.**
`mcp_gate.py:840` sets `agent_id = current_agent_id()` and line 907 uses it as
`from_agent`. But `whoami`'s note says:

> "This session is named X, but your messages go out as Y — that is the address to
> give people."

That is false. Replies come back to the per-tab session address, which dies with
the tab. This is the single most consequential defect: it tells the user to hand out
an address that their own messages do not originate from.

**F2 — the primary slot reads nothing.**
`inbox_addresses()` (`mcp_gate.py:540`) returns `[current_agent_id()]`
unconditionally; there is no primary branch. But `skills/antrozous-inbox/SKILL.md`
step 3 instructs the model to arm a second Monitor on `account_ws_url` when
`is_primary`, "because this session drains both inboxes." It does not. The doorbell
rings and the subsequent `check_inbox` looks at a different queue.

**F3 — the relay has no durable store.**
`inboxes` is a plain in-memory dict. `BACKUP_FILE = "messages.json"` is read at
startup (`server.py:75-77`) and never written — there is no writeback anywhere in
the file. `docs/encryption-design.md` still says the relay "mirrors it to
messages.json"; that stopped being true at some point and nothing caught it. A
redeploy drops every message, key, and alias.

**F4 — session identity is keyed to the OS process.**
Records live at `sessions/<pid>.json` and liveness is `_pid_alive(pid)`. Killing a
terminal destroys the identity, so `claude --resume` returns as a different agent
with a different queue.

A fifth, less visible: `suggest_session_name` picks the lowest ordinal not held by a
*live* session, so ordinals are reused. A new tab can claim the name of a closed one
and silently inherit its queue — the exact cross-session drain that
`inbox_addresses()`'s docstring refuses to perform, arriving through the back door.

## 3. The model

Three concepts, no more.

**Fingerprint** — unchanged. Key-derived, device-wide, the root of every
authorization decision.

**Account name** — chosen once, on first run. It is the stem every session id is
built from, and the alias claimed on the relay. It is *not* a per-session choice and
cannot be changed by the startup prompt.

**Session id** — `<account-name>-<n>.<fingerprint>`, derived, never prompted for,
never handed out. This is the queue a session polls and the `from_agent` on its
outbound mail.

The separator is a hyphen, not a dot. `anish-bot.1.e5ox72jb` fails the relay's
`_QUALIFIED_ID_RE` (`server.py:97`), whose name part forbids dots, and that regex
gates `_check_signature`, `publish_keys`, `get_keys`, and `list_inboxes` — a dotted
id fails to authenticate at all. It also breaks client-side: `normalize_name`
truncates at the first dot, so `compose_agent_id(*split_agent_id(x)) != x` and the
ordinal is dropped with no error. `anish-bot-1.e5ox72jb` passes the relay regex
today and needs no flag day.

## 4. Session identity is keyed to the Claude session

Replace the pid-keyed record with a session-keyed one.

- Key: `CLAUDE_CODE_SESSION_ID`, present in the environment Claude Code gives its
  children (confirmed for the Bash tool; MCP stdio servers are spawned the same way
  — see §12 for the check that must pass first).
- Record path becomes `sessions/<claude-session-id>.json`.
- The pid moves *inside* the record and is used only for liveness.

Identity and liveness are now separate questions:

- `live_sessions()` — records whose stored pid is alive. Used for the peer list and
  for nothing else.
- The record itself persists after the process exits, because the session may
  resume.

`claude --resume` therefore returns as the same agent, polling the same queue, and
drains whatever arrived while the terminal was dead. This is what makes an ephemeral
session address survivable, and it removes most of the reply-after-close stranding
that would otherwise need a queue-adoption mechanism.

**Records are never garbage-collected.** They are a few hundred bytes each and a
Claude session is resumable indefinitely, so any TTL is a guess about resumability
that would silently orphan a queue. Accumulation is the cheaper error.

## 5. Naming: a monotonic counter

The ordinal comes from a counter in `~/.antrozous/identity.json`, incremented once
per new Claude session and never reused.

Rejected alternatives:

- *Lowest free among live sessions* (today's behaviour) — reuses ordinals, so a new
  session can inherit a dead one's queue. That is the bug, not the feature.
- *Lowest inbox with nothing pending* — needs an authenticated relay round-trip at
  startup, which the SessionStart hook cannot make (no crypto, no ticket), and it
  races: two sessions launching together both see the same ordinal free.
- *Random suffix* — avoids reuse but costs readability for nothing, since no one
  ever hands out a session id.

A resumed session does not increment; it reads its ordinal from its own record.

## 6. The account inbox and the primary slot

**Correction to an earlier conclusion in this design's discussion: the primary slot
cannot simply be deleted.** It has to be fixed.

The alias forces it. `/resolve/{name}` (`server.py:403`) maps a bare name to a
fingerprint, and `resolve_peer` composes `<name>.<fingerprint>` client-side. So
anyone who addresses you as `anish-bot` sends to `anish-bot.e5ox72jb` — the account
address — and first-claim-wins means that alias can never be repointed at a session.
The account address is therefore permanently receivable, and if nothing drains it,
cold mail from new contacts is invisible.

So:

- The account address remains a real inbox: the **front door**, holding mail from
  people who addressed you by your public name.
- Exactly one live session drains it. That is what `primary` means, and
  `inbox_addresses()` must actually return it — the one-line fix that makes F2's
  documentation true.
- Session queues stay strictly private. A session never reads another live
  session's mail.

The line is: shared front door, private rooms. Draining the front door is not a
cross-session drain, because the front door belongs to no session.

Primary becomes well-defined under session-keyed records: the holder is the session
whose record carries `primary: true` **and** whose stored pid is alive. A vacant or
dead-held slot is claimable, as `claim_primary` already does.

## 7. Startup UX

**First run** — the existing blocking popup, unchanged in mechanism. It names the
account. Its copy changes to say so plainly: this is your address, it is permanent,
and sessions will be numbered from it.

**Every run after** — no popup. A non-blocking one-line announcement of the full
session id:

```
antrozous: you are anish-bot-3.e5ox72jb (front door: anish-bot.e5ox72jb)
```

Removing the per-session prompt is what makes the account name stable. It is also
what removes the free-text field that produced `anish-bot-1` as an account name in
the first place.

## 8. `set_identity`

Becomes exclusively an account-name operation: it changes the stem that session ids
are built from, and nothing else. It does **not** move the alias — `aliases` uses
`setdefault` (`server.py:394`), so the first claim wins and is never reassigned. A
renamed account keeps receiving mail at the old alias, which is correct: the alias
is bound to the fingerprint, not to the name, and old contacts still reach the right
device. `set_identity` must say so rather than implying the public name changed.

Session renaming disappears, because a derived, ephemeral, never-handed-out id has
nothing worth renaming.

## 9. Data shapes

`~/.antrozous/identity.json`

```json
{
  "agent_id": "anish-bot.e5ox72jb",
  "account_name": "anish-bot",
  "session_counter": 7,
  "fingerprint": "e5ox72jb",
  "confirmed": true,
  "created_at": "...",
  "renamed_at": "...",
  "previous_agent_id": "agent-anishrane"
}
```

`~/.antrozous/sessions/<claude-session-id>.json`

```json
{
  "claude_session_id": "a133d3ce-293b-4c3a-9a83-5d5ec88a51ef",
  "agent_id": "anish-bot-3.e5ox72jb",
  "pid": 39867,
  "started_at": "...",
  "last_seen_at": "...",
  "primary": true
}
```

The ordinal is not stored separately — it is already the tail of `agent_id`, and a
second copy could disagree with the first.

`last_seen_at` is refreshed on each session start so a human reading the directory
can tell a long-dormant session from a recent one, even though nothing prunes.

## 10. Migration

Existing installs have an account id whose name may already carry an ordinal.

1. On first run under the new scheme, if `account_name` is absent, derive it from
   `agent_id`.
2. If that name matches `^(.*)-(\d+)$`, offer once — through the existing approval
   popup, never silently — to strip the trailing ordinal (`anish-bot-1` →
   `anish-bot`). Declining keeps the current name verbatim.
3. Seed `session_counter` from the highest ordinal found in the old
   `sessions/<pid>.json` records, so a rename cannot recycle an ordinal that already
   has a queue on the relay. This is the one and only read of those records.
4. After seeding, old `sessions/<pid>.json` records are ignored for every other
   purpose and left in place. They are pruned by nothing and cost nothing; adding a
   deleter is a risk with no payoff.

The alias already claimed on the relay does not move — first claim wins and is never
reassigned. If the account name is changed, the old alias remains pointed at the
same fingerprint, so old contacts still reach the right device.

## 11. What gets deleted

- The per-session identity popup (§7).
- Session renaming in `set_identity` (§8).
- `suggest_session_name` / `suggest_session_id` ordinal search, replaced by the
  counter (§5).
- Three of `whoami`'s four `note` branches — the account/session divergence they
  explain stops existing.
- `_pid_alive`-as-identity (`identity.py:74`), reduced to a liveness helper.

Explicitly **not** deleted: the primary slot (§6), `other_queues()` and the
`/inboxes` view, which become the orchestration surface.

## 12. Testing

The listener work established the pattern: subprocess the hook and the CLI, redirect
`ANTROZOUS_HOME` at a temp dir, and assert on real output.

- Ordinal counter: increments per new session, never reuses, survives a rename.
- Resume: same `CLAUDE_CODE_SESSION_ID` yields the same `agent_id` and the same
  queue; a different one yields the next ordinal.
- Liveness: a record with a dead pid is not a live session but is still resolvable.
- Primary: claimable when vacant or dead-held; not stealable from a live holder;
  `inbox_addresses()` returns the front door only for the holder.
- Migration: `anish-bot-1` → `anish-bot` on approval, unchanged on decline, counter
  seeded above existing ordinals.
- Grammar: the hyphen form round-trips through `split_agent_id`/`compose_agent_id`
  and matches the relay's `_QUALIFIED_ID_RE`; the dotted form is rejected loudly
  rather than silently truncated.
- Hostile files: the identity and session records get the same treatment
  `listener.json` now has — unreadable, non-UTF-8, directory-in-place, non-object
  JSON must all degrade rather than raise.

## 13. Out of scope

- **Project-scope overrides** (`.antrozous/identity.json`, `_ensure_git_excluded`,
  `shadowed`, `drop_project_override`). The largest single concept in `identity.py`
  and a candidate for removal, but orthogonal to this work. Left alone.
- **Dead-session queue adoption.** Mostly obviated by §4; the residue is sessions
  never resumed, which `/inboxes` already surfaces and `check_inbox(agent_id=…)`
  already drains by hand.
- **Relay durability** (F3). `BACKUP_FILE` promising a persistence that does not
  exist is a real defect, but it is a relay change with its own blast radius.
- **Archive-on-consume.** The only place a message can survive both a consume and a
  relay redeploy is the client, and `~/.antrozous/inbox/` is currently just the
  attachment blob cache. Worth doing; not here.
