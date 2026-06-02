# Review: `config-overhaul` (`main..config-overhaul`)

> Note: this file previously held a review of an **earlier** state of the branch
> (6 commits, `render_command`/flat-regex/mtime-reload). That branch has since
> been reworked — regex is now anchored-by-default, control chars are rejected,
> reload uses SHA-256 content hashing, and deny reasons carry the rule index.
> Most of the prior findings are resolved. This is a fresh review of the current
> 11-commit branch.

Scope: per-token matchers replacing flat-regex rules, unified `deny`/`allow`
arrays, SHA-256 content-hash hot-reload, `sudix --help`. Reviewed `policy.rs`,
`config.rs`, `server.rs`, `scoping.rs`, both binaries, the socket round-trip
test, and the docs.

**Verification:** `cargo test` (113 pass), `cargo clippy --all-targets` (clean).

**Overall:** strong. The per-token matcher model (Literal / anchored-Regex /
Rest) closes the path-spoofing and substring-match holes the old flat-regex
model had, and the matcher/rule/policy split is idiomatic and readable. The
findings below are mostly **documentation drift** — the docs describe a
cache-preservation behavior the code deliberately does not implement (the plan
doc confirms the *code* is correct) — plus one real resource leak.

---

## Issues (highest severity first)

### 1. Docs claim the approval cache survives reloads; the code always clears it — sev 5

Three doc locations assert the approval cache and rate state are *preserved*
when allow rules are unchanged:

- [README.md:101](README.md#L101): "the approval cache and rate-limit state are preserved when the allow rules are unchanged."
- [README.md:168](README.md#L168): "allow-unchanged reloads preserve the approval cache and rate state."
- [docs/OPERATIONS.md:91-92](docs/OPERATIONS.md#L91): "the approval cache and rate-limit state survive reloads where the allow rules are unchanged."

The code does the opposite. [server.rs:113-118](crates/sudix/src/server.rs#L113-L118)
unconditionally resets `*guard = ApprovalState::new()` on *any* content change —
there is no allow-rules comparison anywhere. And this is **intentional**:
[docs/PLAN-config-overhaul.md:535-536](docs/PLAN-config-overhaul.md#L535-L536)
says `rule_index` stability is handled "by clearing `ApprovalState` on every
successful swap. Do not try to remap indices." The test
`approval_state_cleared_on_rule_change` ([server.rs:1158](crates/sudix/src/server.rs#L1158))
asserts the clear directly.

So the docs are wrong, not the code. Worse, it mis-leads in the unsafe
direction: a reader believes an unrelated edit keeps their auto-approve cache,
when every edit drops it (the conservative, correct behavior).

**Fix:** replace all three claims with "any content change resets the approval
cache and rate-limit state." The "identical-content save is a no-op" sentence is
accurate — the SHA-256 fast path at [server.rs:99](crates/sudix/src/server.rs#L99)
genuinely skips the reset — so keep that part.

### 2. Rate-limit window grows unbounded for rules with `rate_per_min = 0` — sev 4

`record_approval` always pushes a timestamp into `guard.rate[rule_index]`
([scoping.rs:159](crates/sudix/src/scoping.rs#L159)); `record_cache_hit` does the
same ([scoping.rs:172](crates/sudix/src/scoping.rs#L172)). Pruning lives only in
`is_rate_limited`, which **returns early when `limit == 0`** before reaching the
prune loop ([scoping.rs:120-122](crates/sudix/src/scoping.rs#L120-L122)).

A rule with `cache_ttl_secs > 0` but `rate_per_min = 0` (cache, no rate cap — a
natural config) therefore accumulates one `Instant` per execution in a
`VecDeque` that is never drained, for the daemon's lifetime. The comment at
[scoping.rs:158](crates/sudix/src/scoping.rs#L158) calls this "harmless"; it is
an unbounded leak.

**Fix:** gate both rate-window writes on `rate_per_min > 0`, mirroring how the
cache write is already gated on `ttl > 0` at
[scoping.rs:153-156](crates/sudix/src/scoping.rs#L153-L156). `record_cache_hit`
will need `scopes`/`rule_index` to check the limit (see #3).

### 3. `record_cache_hit` duplicates the tail of `record_approval` — sev 2

`record_cache_hit` exists only to push the rate-window timestamp that
`record_approval` already pushes — its body is the tail of `record_approval`.
Two functions that must stay in lock-step (both need the `rate_per_min == 0`
guard from #2) is the kind of duplication that caused the missing guard in the
first place.

**Fix:** collapse the rate-window bump into one private helper
(`note_execution(guard, scopes, rule_index, now)`) called by both paths, so the
zero-rate guard lives in exactly one spot.

### 4. `--reason` / `--otp` swallow `--` as their value — sev 2

[sudix.rs:58-63](crates/sudix/src/bin/sudix.rs#L58-L63): both flags consume the
next token unconditionally. `sudix --reason -- id` takes `--` as the reason,
then fails "no command given" because the real separator is gone. Fail-closed
and quotable, but the error is confusing and untested.

**Fix:** reject `--` as a flag value (or document the restriction). Low priority.

### 5. Doc-comment pipelines list empty-argv denial twice — sev 1

`handle_request` denies+audits empty argv at
[server.rs:186-191](crates/sudix/src/server.rs#L186-L191); `Policy::evaluate`
checks it again at [policy.rs:191-195](crates/sudix/src/policy.rs#L191-L195).
The second is legitimately defensive (the policy layer is unit-tested
standalone), but both doc-comment pipelines list "empty argv → Denied" as step
1, which reads as if one path is dead. A one-line note that the policy layer
repeats the check for direct callers would remove the confusion. Informational.

---

## Done well

- **Per-token matcher model.** Literal / Regex (compile-time `^(?:…)$` anchor) /
  Rest, with `Rest`-only-final enforced in `Rule::new`. The `rm`/`confirm`
  non-collision test ([policy.rs:411](crates/sudix/src/policy.rs#L411)) and the
  implicit-anchoring tests target exactly the old flat-regex failure modes.
- **Control-char rejection up front** ([policy.rs:196](crates/sudix/src/policy.rs#L196)),
  checked once before any rule, tested for argv[0] and later args.
- **Single-flight reload:** `last_hash` held across the load
  ([server.rs:92-119](crates/sudix/src/server.rs#L92-L119)) with a documented
  lock order; fast-path covered by `same_content_skips_reload`.
- **Fail-closed reload:** bad TOML keeps the old policy and refuses the
  triggering request (`reload_failure_fails_closed_and_keeps_old_policy`).
- **`deny_unknown_fields`** on every config struct plus the `{ re, rest }`
  exactly-one-key check in `raw_to_token` → malformed rules fail at load.
- **`serve`/`serve_with_registry` dedup** via `bind_and_log` (a prior-review
  finding, now fixed); the read-lock is scoped to cloning `agent_uids` and
  dropped before I/O.
- Tests are short, logic-free, use a fake clock instead of `sleep`, and mock
  only at the `Approver` seam.

## Out of scope (pre-existing, not touched here)

- `approver_uids` is parsed and validated-non-empty but never enforced on the
  `RegisterAgent` path — any `agent_uids` caller can register as the approving
  agent ([server.rs:587](crates/sudix/src/server.rs#L587) checks only
  `agent_uids`). `approval.rs` is unchanged in this branch, so this predates it;
  flagged only because the README sells "Agent vs. approver UID separation" as a
  delivered feature.

## Priority

Fix before merge: **#1** (docs actively mislead about cache behavior) and **#2**
(unbounded leak). #3–#5 are cleanup.
