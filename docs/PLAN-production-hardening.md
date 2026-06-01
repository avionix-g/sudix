# PLAN: Production hardening of the sudix broker

## Intent

`sudix` is a privileged-action broker: a coding agent requests a specific
command, a root daemon checks it against server-side policy, asks a human to
approve that exact command, runs it as root, and audits the result. The core
pipeline (peer-cred auth → policy → approval → execute → audit) works end to end
and is tested, but several things in `NEXT_STEPS.md` must change before this
guards real root access.

This plan addresses **every** entry in `NEXT_STEPS.md`, plus the UID caveat,
in an order chosen so that each step builds on a foundation laid by an earlier
one. The single largest enabler is **config externalization** (step 1): once
policy, allowed UIDs, cwd rules, approval method, and scoping all live in a
root-owned config file, the remaining steps slot into that structure instead of
inventing their own ad-hoc inputs.

### Decisions locked during planning

These were decided with the user. Implementers must not relitigate them; if a
decision turns out to be unimplementable, **stop and ask**.

1. **Config format/location:** TOML at `/etc/sudix/policy.toml`, root-owned,
   not world-writable. New dependency: `toml`.
2. **Config failure is fatal:** missing, unparseable, or invalid config → the
   daemon **refuses to start** (fail closed). No fallback to compiled defaults.
   A `default-config` subcommand prints a starter config that reproduces today's
   compiled-in behavior, so "behaves like it does now" is one command away — but
   it is never implicit.
3. **cwd validation:** canonicalize the client-supplied cwd, confirm it exists
   and is a directory; reject otherwise. (No prefix allowlist in this plan; the
   config schema leaves room to add one later.)
4. **UID caveat:** replace the single `allowed_uid` with two configured sets —
   **agent UIDs** (may submit requests) and **approver/human UIDs** (whose
   presence the approval step is meant to prove). Default config makes them the
   same single uid, reproducing today's "you, sitting here" model. See Step 2.
5. **Approval methods are config-selected and mutually exclusive:**
   `method = "zenity"` or `method = "totp"`. Exactly one approver runs.
6. **TOTP rides the existing one-shot protocol** via an optional `otp` field on
   `Request`. No challenge-response, no multi-message connection. Rationale is
   recorded in Step 6 — do not "upgrade" it to challenge-response.
7. **TOTP secret** lives in a root-owned `0400` key file; an `enroll`
   subcommand generates it and prints the `otpauth://` provisioning URI.

### Cross-cutting invariants (must hold after every step)

- **Fail closed everywhere.** Any error, missing input, or ambiguity denies /
  refuses to start. This is already the codebase's discipline; preserve it.
- **The agent cannot forge an authorization.** Policy, UID sets, cwd validation,
  and approval all run inside the root daemon. The client remains pure transport
  and holds no credential.
- **Lints stay green.** The workspace denies `clippy::pedantic`, `complexity`,
  `correctness`, `perf`, `style`, `suspicious`, and **forbids `unsafe_code`**.
  No `unsafe`. Add `# Errors` docs on new public fallible fns (the workspace
  allows `missing-errors-doc`, but existing code documents them anyway — match
  the surrounding style).
- **Every decision is audited**, including new denial reasons (bad-uid-role,
  bad-cwd, otp-failed, rate-limited, etc.).
- **`just prep` passes** (`format`, `lint`, `machete`, `build`, `test`) before
  each commit. `cargo machete` will flag unused deps — only add a dep in the
  same commit that first uses it.

---

## Overview

Steps map 1:1 to commits, in this order:

1. **Config scaffolding + externalize policy.** Introduce `config` module,
   `/etc/sudix/policy.toml`, `default-config` subcommand. Move the allowlist /
   denylist out of `sudixd.rs` into config. (NEXT_STEPS #1)
2. **Agent vs. approver UID sets.** Replace `allowed_uid: u32` with
   `agent_uids` / `approver_uids`, sourced from config. (UID caveat)
3. **Validate cwd.** Canonicalize + existence/dir check before executing.
   (NEXT_STEPS #2)
4. **Approval scoping: TTL, rate limiting, approval cache.** Server-side, config
   driven. (NEXT_STEPS #3)
5. **Config-selected approver.** Wire `method = "zenity" | "totp"` so the daemon
   picks the approver from config. Pure plumbing; TOTP impl lands next.
   (prepares NEXT_STEPS #4)
6. **TOTP approver + `otp` field + `enroll`/secret.** Headless approval path.
   (NEXT_STEPS #4)
7. **Concurrency: per-connection threads + serialized approval queue.**
   (NEXT_STEPS #6)
8. **systemd unit + socket activation.** (NEXT_STEPS #5)
9. **Documentation: testing, building, releasing.** (NEXT_STEPS docs)

Steps 1–3 are sequential (each consumes the config struct the prior extended).
Steps 4, 5, 7, 8, 9 each depend on 1. Step 6 depends on 5. Step 7 should land
before heavy reliance on TTL/cache under load but does not strictly block them.

A note on commit discipline: each step is one logical commit. If a step's diff
gets large (esp. 1, 6, 7), it's acceptable to split into a "scaffold/struct"
commit and a "wire it in" commit, but keep the build green at each commit.

---

## Step 1 — Config scaffolding & externalize policy

**Commit title:** `Load policy from a root-owned TOML config`

**Intent:** Policy must be reviewable as data and changeable without a rebuild.
This step also establishes the config struct that every later step extends, so
design it to grow.

**New dependency:** add to `[workspace.dependencies]` in the root `Cargo.toml`:
```toml
toml = "0.8"
```
(Pin the latest stable `toml` at implementation time; `0.8` is the floor.) Add
`toml.workspace = true` to `crates/sudix/Cargo.toml`. `serde`/`serde_json` are
already present.

**Files to touch:**
- `crates/sudix/src/config.rs` (new module)
- `crates/sudix/src/lib.rs` (add `pub mod config;` and re-exports)
- `crates/sudix/src/bin/sudixd.rs` (load config; add `default-config` subcommand)
- `crates/sudix/Cargo.toml`, root `Cargo.toml` (dep)
- `README.md` (config section — defer detailed docs to Step 9, but fix the
  now-false "lives in src/bin/sudixd.rs" line)

**Logic to implement:**

Create a `config` module with serde-`Deserialize` types mirroring the file:

```rust
// config.rs (shape; exact fields grow in later steps)
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Allow rules as token lists, e.g. [["pacman","-S","**"], ...].
    pub allow: Vec<Vec<String>>,
    /// Hard-denied program basenames.
    pub hard_deny: Vec<String>,
    // UID sets added in Step 2, cwd in Step 3, scoping in Step 4,
    // approval in Step 5/6. Add fields here as those steps land.
}
```

- Use `#[serde(deny_unknown_fields)]` so a typo'd key is a hard error, not a
  silent default — consistent with fail-closed.
- A `FileConfig::load(path: &Path) -> Result<FileConfig, ConfigError>` that
  reads the file and `toml::from_str`s it. Define a `ConfigError` enum
  (`Io`, `Parse`, `Invalid(String)`) implementing `std::error::Error` +
  `Display`. (A hand-rolled enum keeps deps minimal; do **not** add `thiserror`
  unless a later step clearly needs it.)
- A conversion `FileConfig -> server::Config` (or a `build()` method) that
  constructs `Policy` via `Rule::new` for each allow entry. **`Rule::new`
  already validates `**` placement** ([policy.rs:48-68](../crates/sudix/src/policy.rs#L48-L68));
  surface its `Err` as `ConfigError::Invalid` with the offending rule's index in
  the message. This satisfies NEXT_STEPS #1's "validate `**` placement at load
  time."
- **Permission check on the config file:** before trusting it, stat the file and
  refuse if it is group- or world-**writable** (mode `& 0o022 != 0`) or not
  owned by root (uid 0). A world-writable policy file is a root-escalation hole.
  Emit a clear `ConfigError::Invalid`. (Use `std::os::unix::fs::MetadataExt`;
  no `unsafe`.) Gate this so tests can point at a tempfile they own — see
  Testing note.

In `sudixd.rs`:
- Config path from `$SUDIX_CONFIG`, default `/etc/sudix/policy.toml`.
- `main` parses argv first: a `default-config` subcommand prints a starter
  config to stdout and exits 0. The starter config must reproduce **exactly**
  today's compiled `default_policy()` allowlist + denylist
  ([sudixd.rs:23-49](../crates/sudix/src/bin/sudixd.rs#L23-L49)) and (after later
  steps) the single-uid default. Keep a single source of truth: generate the
  starter text from a `const`/function so it can't drift from the schema.
- Otherwise: load config, build `server::Config`, `serve(...)`. On any
  `ConfigError`, print it and `ExitCode::FAILURE` — **fail closed**.
- Delete the compiled-in `default_policy()` from `sudixd.rs` (its content moves
  into the starter-config generator).

**The permission check + test seam:** add a parameter or env hook so the
ownership/mode enforcement can be relaxed under test (e.g. a
`FileConfig::load_with_checks(path, enforce_perms: bool)` where production passes
`true`). Do **not** weaken the production default.

**Tests to add (`config.rs` `#[cfg(test)]`):**
- Round-trip: a TOML string with allow/deny parses into the expected `Policy`
  verdicts (reuse `Policy::evaluate` assertions).
- Misplaced `**` in an allow rule → `ConfigError::Invalid` mentioning the rule
  index.
- Unknown key → parse error (proves `deny_unknown_fields`).
- Missing file → `ConfigError::Io`.
- `default-config` output parses back into a valid `FileConfig` and yields the
  same verdicts as the old compiled policy for a handful of sample argvs
  (`pacman -S rg` allowed, `bash -c ...` denied, `id` allowed, `rm -rf /`
  denied). This is the "behaves like it does now" regression guard.
- Perm check (with `enforce_perms=true`): a tempfile made world-writable
  (`chmod 0666`) is rejected. (Owned-by-root can't be asserted in an unprivileged
  test; assert the writable-bit rejection and leave ownership to a comment.)

---

## Step 2 — Agent vs. approver UID sets (the UID caveat)

**Commit title:** `Split allowed uids into agent and approver roles`

**Intent:** Today one `allowed_uid` conflates "who may ask" with "whose presence
approval proves." The NEXT_STEPS UID caveat: if the agent runs under its own
service-account uid, peer-cred proves only "the agent connected," not "the human
is present." Separating the roles makes the deployment's trust model explicit in
config. Default: one uid in both sets → today's behavior.

**Files to touch:**
- `crates/sudix/src/config.rs` (add UID fields)
- `crates/sudix/src/server.rs` (`Config`, `handle_connection`, `peer_uid` use)
- `crates/sudix/src/bin/sudixd.rs` (starter config gains uid fields; drop
  `SUDIX_ALLOWED_UID`-only path)
- tests

**Logic to implement:**

- Config gains:
  ```toml
  agent_uids    = [1000]   # uids permitted to submit requests
  approver_uids = [1000]   # uids whose live presence approval is meant to prove
  ```
  Both default in the starter config to the invoking user's uid (the
  `default-config` generator can substitute `$(id -u)` at print time, or print a
  `1000` placeholder with a comment — pick the placeholder; do not shell out).
- `server::Config`: replace `allowed_uid: u32` with
  `agent_uids: Vec<u32>` and `approver_uids: Vec<u32>` (or `HashSet<u32>`; a
  `Vec` with `.contains` is fine at this scale and simpler).
- `handle_connection` ([server.rs:145-153](../crates/sudix/src/server.rs#L145-L153)):
  the peer uid must be in `agent_uids`, else deny "caller uid not authorized"
  (unchanged message, so the existing integration test
  [socket_roundtrip.rs:98-110](../crates/sudix/tests/socket_roundtrip.rs#L98-L110)
  still passes once it's updated to the new `Config` shape).
- **How `approver_uids` is enforced depends on the approver:**
  - `ZenityApprover`: the dialog runs in the human's desktop session; presence is
    inherent. `approver_uids` is advisory/audited here — record it but it doesn't
    gate the GUI. Document this honestly.
  - `TotpApprover` (Step 6): the secret is shared with the human(s); a valid code
    proves possession. `approver_uids` documents *who* that is. Enforcement of
    "the code came from an approver" is out of scope (TOTP is a possession
    factor, not an identity-of-connection factor) — state this limitation in the
    audit/docs rather than pretending otherwise.
  - **Concrete enforcement this step does add:** when `agent_uids` and
    `approver_uids` are disjoint (the "agent has its own uid" deployment), the
    daemon must **require a non-GUI second factor** — i.e. refuse to start with
    `method = "zenity"` when the sets are disjoint, because a desktop dialog can't
    prove a human who isn't the connecting agent is present. This is the
    teeth behind the caveat: misconfiguration fails closed at startup.
- Remove the `allowed_uid()` env helper from `sudixd.rs`; UID config now comes
  from the file. (Keep `SUDIX_ALLOWED_UID` working as an override **only** if
  trivial; otherwise drop it and note the migration in README. Prefer dropping —
  config is the source of truth now.)

**Tests to add:**
- `server.rs` unit tests already pass a `Config`; update `test_cfg` to the new
  fields. Add: a request from a uid not in `agent_uids` is denied before policy
  (extend the existing reasoning).
- `config.rs`: disjoint `agent_uids`/`approver_uids` + `method="zenity"` →
  `ConfigError::Invalid` (startup refusal). Overlapping sets + zenity → ok.
- Update `socket_roundtrip.rs` `spawn_broker` to the new `Config` shape; the
  `wrong_uid` test now puts the foreign uid outside `agent_uids`.

---

## Step 3 — Validate cwd

**Commit title:** `Canonicalize and validate client-supplied cwd before exec`

**Intent:** The client supplies `cwd` and the daemon `current_dir`s into it
verbatim before executing as root ([server.rs:87-91](../crates/sudix/src/server.rs#L87-L91))
— attacker-influenced input. Canonicalize and confirm it's an existing
directory; reject otherwise.

**Files to touch:**
- `crates/sudix/src/server.rs` (`handle_request` / `execute`)
- tests

**Logic to implement:**
- In `handle_request`, **before approval** (so the human sees a validated cwd,
  and a bad cwd never prompts), validate `req.cwd`:
  - `std::fs::canonicalize(&req.cwd)` → on `Err`, deny with
    `"invalid working directory"` and audit `denied-cwd`.
  - The canonicalized path must be a directory (`metadata.is_dir()`), else deny.
- Pass the **canonicalized** path to `Command::current_dir`, not the raw client
  string. `execute` should take the validated `&Path` rather than reading
  `req.cwd` itself — adjust its signature.
- Keep the displayed cwd in the approval prompt the **canonicalized** one too,
  so the human approves what will actually be used (update `prompt_text` caller
  or pass the resolved cwd through). Minimal: validate in `handle_request`,
  thread the resolved `PathBuf` to both `execute` and the prompt.
- Audit the resolved cwd, not the raw input (the audit `Entry.cwd` currently
  borrows `&req.cwd` — pass the resolved string instead for executed/denied-cwd
  outcomes). Keep raw cwd out of the executed record to avoid confusion.

**Tests to add (`server.rs`):**
- A request with a non-existent cwd → `Denied`, approver **not** consulted
  (mirror `policy_denial_skips_approval_and_execution`), audited `denied-cwd`.
- A request whose cwd is a **file** not a dir → `Denied`.
- Happy path: cwd `"."` resolves and the command still runs (existing
  `approved_command_executes_and_returns_output` should keep passing; `.`
  canonicalizes to the test's cwd).

---

## Step 4 — Approval scoping: TTL, rate limiting, approval cache

**Commit title:** `Add server-side approval TTL, rate limiting, and caching`

**Intent:** So the human isn't prompted for every invocation of a low-risk
command, while keeping enforcement **server-side where the agent can't reach**.
Per NEXT_STEPS #3.

**Design — keep it simple and fail-closed.** Three independent, opt-in,
per-rule knobs, all defaulting to "off / no relaxation" (i.e. today's behavior:
prompt every time, no limit):

```toml
[[allow]]
argv          = ["pacman", "-S", "**"]
cache_ttl_secs = 0     # 0 = always prompt (default). >0 = after one approval,
                       # auto-approve identical argv within this window.
rate_per_min   = 0     # 0 = unlimited (default). >0 = max approvals/min for
                       # this rule; over limit => denied (NOT auto-approved).
```

- **Per-rule fields** require `Rule` (or a parallel config row) to carry
  metadata. Cleanest: change the config allow entry from a bare token list to a
  struct:
  ```toml
  [[allow]]
  argv = ["pacman","-S","**"]
  cache_ttl_secs = 300
  ```
  Keep `Rule` (the matcher) unchanged; add a `RuleConfig { rule: Rule, ttl,
  rate }` wrapper, or store scoping in a `Vec` parallel to `Policy.allow`
  indexed by match. Prefer a `Policy` that owns `Vec<ScopedRule>` where
  `ScopedRule { rule: Rule, ttl_secs: u64, rate_per_min: u32 }`. **`evaluate`
  must return *which* rule matched** so the scoping engine can consult its
  knobs — change `Verdict::Allowed` to `Verdict::Allowed { rule_index: usize }`
  (update all match sites: server.rs, tests).
- **Approval cache (TTL):** keyed by `(rule_index, argv exact)` →
  last-approved `Instant`. On a match with `ttl>0` and a fresh cache entry,
  **skip the approver** and audit `approved-cached` (still audit — the record
  must show it ran without a fresh human gate). On expiry, prompt again and
  refresh. `**`-bearing rules: key on the **exact argv**, not the rule, so
  `pacman -S rg` being cached does not auto-approve `pacman -S evil`. This is the
  crucial safety property — state it in a comment.
- **Rate limiting:** per `rule_index`, a sliding window (a small ring/`VecDeque`
  of recent approval timestamps). Over the limit → **deny** (`denied-rate`),
  never silently allow. Counts *approvals/executions*, not requests.
- **State location:** all this state is mutable and shared. Today's accept loop
  is single-threaded ([server.rs:124-133](../crates/sudix/src/server.rs#L124-L133)),
  so a `RefCell`/owned `struct` threaded through `handle_request` works now; but
  Step 7 introduces threads. **Design the scoping state behind a `Mutex` from
  the start** (a `struct ApprovalState { cache: HashMap<...>, rate:
  HashMap<...> }` wrapped in `Mutex`), so Step 7 doesn't have to retrofit it.
  Pass `&Mutex<ApprovalState>` (or an `Arc` once Step 7 lands) into
  `handle_request`. Keep lock hold-times short — never hold the lock across the
  (blocking) approver call.
- **Clock:** use `std::time::Instant` for TTL/rate (monotonic). Make the clock
  injectable for tests (a `Clock` trait or a `now: fn() -> Instant`
  parameter) so TTL/rate tests don't sleep. Minimal viable: a tiny trait with a
  real impl and a fake.

**Files to touch:**
- `crates/sudix/src/policy.rs` (`Verdict::Allowed { rule_index }`, `ScopedRule`)
- `crates/sudix/src/config.rs` (allow-entry struct with ttl/rate)
- new `crates/sudix/src/scoping.rs` (or fold into server) — `ApprovalState`,
  cache + rate logic, injectable clock
- `crates/sudix/src/server.rs` (`handle_request` consults scoping)
- `crates/sudix/src/audit.rs` (new outcomes are just strings — no change needed
  beyond passing them)
- tests

**Tests to add:**
- Cache: with `ttl=60`, two identical approved requests → approver called
  **once**, second audited `approved-cached`. A *different* argv under the same
  `**` rule still prompts (proves exact-argv keying).
- Cache expiry: advance the fake clock past ttl → approver called again.
- Rate: `rate_per_min=2`, three approvals in-window → third is `denied-rate`,
  approver consulted at most twice.
- Defaults (`ttl=0`, `rate=0`) reproduce today's behavior (every request
  prompts, none rate-limited) — regression guard.

---

## Step 5 — Config-selected approver (plumbing for headless)

**Commit title:** `Select the approver from config (zenity|totp)`

**Intent:** Decouple "which approver" from the binary. Pure plumbing so Step 6's
TOTP impl drops into a seam that already exists. No behavior change when
`method = "zenity"` (the default).

**Files to touch:**
- `crates/sudix/src/config.rs` (`[approval] method = "zenity"`)
- `crates/sudix/src/bin/sudixd.rs` (construct the chosen `Approver`)
- `crates/sudix/src/approval.rs` (an `ApprovalMethod` enum + a constructor
  `fn approver_for(method) -> Box<dyn Approver>`; TOTP arm stubbed to
  `unimplemented!`/returns an error until Step 6 — but prefer to land 5 and 6
  together if the stub would break the build's "no dead code" expectations.
  Acceptable to **merge Step 5 into Step 6** if separating them leaves a
  non-functional `totp` value. Default to merging if in doubt.)

**Logic to implement:**
- Config:
  ```toml
  [approval]
  method = "zenity"   # "zenity" | "totp"
  ```
  Deserialize into an enum `#[serde(rename_all = "lowercase")]`.
- `sudixd.rs` builds the approver from config and passes it to `serve`. `serve`
  already takes `&dyn Approver` ([server.rs:112](../crates/sudix/src/server.rs#L112))
  — no server change needed.
- Recall the Step 2 invariant: disjoint agent/approver UID sets + `zenity` →
  refuse to start. That check belongs with config validation; ensure it sees the
  `method` field.

**Tests to add:**
- Config with `method = "totp"` parses to the TOTP variant; bad method string →
  parse error.
- (Behavioral tests for each approver live in Step 6 / existing zenity tests.)

---

## Step 6 — TOTP approver, `otp` field, secret + enroll

**Commit title:** `Add TOTP headless approval path`

**Intent:** zenity needs a desktop. Add an out-of-band, headless approval path
(NEXT_STEPS #4) that keeps the fail-closed contract. The human reads a code from
an authenticator app; the daemon verifies it against a root-owned shared secret.

**Why the existing one-shot protocol, not challenge-response (locked decision):**
TOTP is a *possession* factor the human already holds — there is nothing for the
daemon to push, so a round trip would only ask the client for a code it could
have sent in the first message. Policy is checked *before* the approver runs
([server.rs:51-64](../crates/sudix/src/server.rs#L51-L64)), so a policy-denied
request never needs a code anyway. The optional field is backward-compatible
(`None` for existing callers) and adds zero protocol states. **Do not convert
this to challenge-response.**

**New dependency:** `totp-rs = "5"` (pin latest stable, `5.7` floor) in
`[workspace.dependencies]`; `totp-rs.workspace = true` in the crate.
`data-encoding` is pulled in transitively by `totp-rs` for base32; do not add it
directly unless needed for the enroll URI (check first — `totp-rs` exposes a
provisioning-URI helper, prefer it).

**Files to touch:**
- root `Cargo.toml`, `crates/sudix/Cargo.toml` (dep)
- `crates/sudix/src/protocol.rs` (`Request.otp: Option<String>`)
- `crates/sudix/src/bin/sudix.rs` (`--otp CODE` flag → `Request.otp`)
- `crates/sudix/src/approval.rs` (`TotpApprover`)
- `crates/sudix/src/config.rs` (`[approval] totp_secret_path`)
- `crates/sudix/src/bin/sudixd.rs` (`enroll` subcommand)
- tests + `socket_roundtrip.rs`/`sudix.rs` test helpers that build `Request`
  must add `otp: None`.

**Logic to implement:**

1. **Protocol:** add `pub otp: Option<String>` to `Request`
   ([protocol.rs:15-24](../crates/sudix/src/protocol.rs#L15-L24)). Use
   `#[serde(default, skip_serializing_if = "Option::is_none")]` so the wire form
   is unchanged when absent and old lines still deserialize. Update the existing
   round-trip tests' literal in
   [protocol.rs:117](../crates/sudix/src/protocol.rs#L117) still parses (it will,
   thanks to `default`). The `otp` is **never audited** (it's a live secret) —
   ensure `audit::Entry` does not gain it.

2. **Client:** `parse_args` learns `--otp CODE` (a leading flag, like
   `--reason`) → `Request.otp = Some(code)`. After `--` or the first bare token,
   `--otp` belongs to the command, consistent with current flag handling
   ([sudix.rs:23-51](../crates/sudix/src/bin/sudix.rs#L23-L51)).

3. **`TotpApprover`:**
   - Holds the secret (loaded once at startup from `totp_secret_path`, a
     root-owned `0400` file; reuse Step 1's perm check — refuse a
     group/world-readable or non-root-owned secret).
   - `approve(req)`: if `req.otp` is `None` → `false` (fail closed). Else verify
     with `totp-rs` using the standard 30s step and a ±1 step skew window. Return
     the boolean. **No info leak:** a wrong code and a missing code both just
     deny; the daemon does not echo "wrong code" with timing detail beyond the
     normal denial.
   - Replay: within this plan, accept the small replay window inherent to TOTP
     (a code is valid ~30–90s). A used-code cache is **out of scope**; note it as
     a future hardening in a code comment. (The peer-cred + 0600 socket bound the
     exposure.)

4. **`enroll` subcommand** (`sudixd enroll`): generate a random secret, write it
   to `totp_secret_path` with mode `0400` owned by root (the daemon runs as root
   when enrolling), and print the `otpauth://totp/...` provisioning URI (and
   optionally an ASCII-QR if `totp-rs` offers it cheaply — otherwise just the
   URI; do not add a QR dep). Refuse to overwrite an existing secret unless a
   `--force` flag is given (fail safe against clobbering a working enrollment).

5. **Config:**
   ```toml
   [approval]
   method = "totp"
   totp_secret_path = "/etc/sudix/totp.key"
   ```
   When `method = "totp"`, `totp_secret_path` is required and the file must exist
   and pass the perm check at startup — else **refuse to start**.

**Tests to add:**
- `approval.rs`: a `TotpApprover` built from a known secret approves a code
  generated from that same secret/time (use `totp-rs` to generate the expected
  code in-test), rejects a wrong code, rejects `otp = None`.
- `protocol.rs`: a `Request` with `otp = Some(..)` round-trips; an old-style line
  without `otp` still deserializes (`otp == None`).
- `sudix.rs`: `--otp 123456 -- id` parses into `otp = Some("123456")`,
  `argv = ["id"]`; `--otp` after the command stays with the command.
- Config: `method="totp"` without `totp_secret_path` → `ConfigError::Invalid`.

---

## Step 7 — Concurrency: per-connection threads + serialized approval queue

**Commit title:** `Serve connections concurrently with a serialized approval gate`

**Intent:** The accept loop is single-threaded
([server.rs:124-133](../crates/sudix/src/server.rs#L124-L133)), so a slow
approval dialog blocks every other request. Handle connections concurrently, but
**serialize the human approval step** so two dialogs/prompts don't race for the
one human, and so the rate/cache state (Step 4) stays coherent.

**Files to touch:**
- `crates/sudix/src/server.rs` (`serve`, `handle_connection`, shared state)
- tests (`socket_roundtrip.rs` can add a concurrency test)

**Logic to implement:**
- `serve`: for each accepted connection, spawn a thread (`std::thread::spawn`;
  no async runtime — keep deps minimal). Bound concurrency with a simple
  semaphore/counter or a small fixed thread pool if unbounded spawning is a
  concern; a plain thread-per-connection is acceptable for the expected low
  volume — match the "fine at low volume" framing in NEXT_STEPS, but cap it so a
  flood can't exhaust the process. A `std::sync::mpsc` work queue feeding N
  worker threads is the clean version; thread-per-conn with an `Arc<Semaphore>`
  (hand-rolled with `Mutex`+`Condvar`, since std has no semaphore) is also fine.
  **Pick thread-per-connection + a counting gate**; document the choice.
- Shared state (`cfg` policy is read-only → `Arc<Config>`; `ApprovalState` from
  Step 4 → `Arc<Mutex<ApprovalState>>`). `Config` and `Policy` are already
  `Clone`/`Send`-friendly (plain data); make `Approver` `Send + Sync` (the trait
  may need `: Send + Sync` supertraits — `ZenityApprover`/`TotpApprover` are
  zero-state or hold immutable data, so this is mechanical).
- **Serialized approval:** wrap the actual `approver.approve(...)` call in a
  dedicated `Mutex<()>` ("approval mutex") so at most one human prompt is
  outstanding at a time. Policy check, cwd validation, cache lookup, and
  execution run concurrently; only the human-facing prompt is serialized.
  Cache/rate state updates take the `ApprovalState` mutex (short holds), distinct
  from the approval mutex (held across the blocking prompt). Document the lock
  ordering to avoid deadlock (always: approval mutex → state mutex, never the
  reverse; or better, never hold both at once).
- Per-connection errors stay isolated (already the contract) — a panicking
  worker thread must not kill the daemon; `serve` should not join-and-propagate
  worker panics. Consider `catch_unwind` at the worker boundary or simply let
  the thread die with a logged message.

**Tests to add:**
- `socket_roundtrip.rs`: fire N concurrent clients at a broker whose approver
  sleeps briefly; assert all get correct responses and total wall-time is far
  less than N × sleep (proves concurrency) while approvals didn't corrupt
  cache/rate state. Use an approver that records concurrent-entry count and
  assert it never exceeds 1 (proves serialized approval).
- Keep existing single-request tests green.

---

## Step 8 — systemd unit + socket activation

**Commit title:** `Ship systemd unit with socket activation`

**Intent:** Run the daemon as root under supervision, with the runtime dir and
permissions set up by systemd rather than ad-hoc `create_dir_all`
([sudixd.rs:75-80](../crates/sudix/src/bin/sudixd.rs#L75-L80)). NEXT_STEPS #5.

**Files to touch:**
- `dist/systemd/sudixd.service` (new)
- `dist/systemd/sudixd.socket` (new)
- `crates/sudix/src/server.rs` and/or `sudixd.rs` (accept a systemd-passed
  listener fd)
- `README.md` / docs (install instructions — coordinate with Step 9)
- possibly root `Cargo.toml` if a socket-activation helper crate is used

**Logic to implement:**
- `sudixd.socket`:
  ```ini
  [Socket]
  ListenStream=/run/sudix/sudixd.sock
  SocketMode=0600
  # RuntimeDirectory handled by the service; or set DirectoryMode here.
  [Install]
  WantedBy=sockets.target
  ```
- `sudixd.service`:
  ```ini
  [Service]
  Type=simple
  ExecStart=/usr/bin/sudixd
  RuntimeDirectory=sudix          # creates/owns /run/sudix as root, 0700
  RuntimeDirectoryMode=0700
  # Hardening: NoNewPrivileges? No — daemon must exec privileged commands.
  # It legitimately needs full root; keep sandboxing minimal and intentional.
  ```
  **Caution:** the daemon's whole job is to run arbitrary allowlisted commands as
  root, so aggressive systemd sandboxing (`ProtectSystem`, `PrivateTmp`,
  `RestrictSUIDSGID`, capability bounding) will break legitimate approved
  commands. Add only hardening that does **not** constrain the executed child —
  document each directive's rationale. Err toward fewer restrictions with a
  comment, not a copy-pasted hardening block.
- **Socket activation:** when started by systemd with `ListenStream`, fd 3 is the
  pre-bound listener. Detect `$LISTEN_FDS` / `$LISTEN_PID` and adopt the fd
  instead of binding. Two options:
  - Use the `sd-notify` / `libsystemd`-style crate (`sd-notify` is small and
    pure-Rust) **only if** it doesn't pull heavy deps; check `cargo machete` /
    tree.
  - Or hand-roll: read `LISTEN_FDS`/`LISTEN_PID` env, and build a
    `UnixListener` from raw fd 3 via `FromRawFd`. **But `unsafe` is forbidden**
    workspace-wide (`unsafe_code = "forbid"`). `FromRawFd::from_raw_fd` is
    `unsafe`. Therefore **prefer a crate that encapsulates the unsafe** (e.g.
    `sd-notify` + a safe fd adoption, or `listenfd`). **Decision for the
    implementer:** if no maintained crate provides safe fd adoption without
    forcing a `forbid`→`deny` downgrade, fall back to "no socket activation;
    plain `ExecStart` binds the socket itself, systemd provides only
    `RuntimeDirectory` + supervision," and document that socket activation is
    deferred. Do **not** relax the `unsafe` forbiddance. **Stop and ask** if this
    forces a real tradeoff.
- Make `serve` able to take an already-bound `UnixListener` (refactor: split
  `serve(cfg, approver)` into `serve_on(listener, cfg, approver)` +
  `serve(cfg, approver)` that binds then calls `serve_on`). This is useful for
  tests too.

**Tests to add:**
- `serve_on` with a test-provided listener works (lets the integration test bind
  its own socket and hand it in — small refactor win).
- Unit files are static; validate by hand / `systemd-analyze verify` in docs,
  not in `cargo test`. Note this in the commit body.

---

## Step 9 — Documentation: testing, building, releasing

**Commit title:** `Document testing, building, and releasing`

**Intent:** NEXT_STEPS "Documentation" item. Make the project buildable,
testable, and releasable by someone other than the author.

**Files to touch:**
- `README.md` (update Status/Usage/config sections to reflect Steps 1–8)
- `docs/TESTING.md`, `docs/BUILDING.md`, `docs/RELEASING.md` (or one
  `docs/CONTRIBUTING.md` / `docs/OPERATIONS.md` — pick one structure; prefer a
  single `docs/OPERATIONS.md` + an expanded README to avoid doc sprawl)
- Possibly `justfile` (a `release` or `install` recipe)

**Content to write:**
- **Testing:** `just test` / `cargo test`; what the unit vs. integration tests
  cover; how to run the socket round-trip; note tests run unprivileged (peer-cred
  uses the test's own uid). How to test the TOTP path with a known secret.
- **Building:** toolchain (`rust-version = 1.95`, edition 2024), `just build`,
  required system bits (`zenity` for the GUI approver at runtime, not build).
  `just prep` as the pre-commit gate.
- **Releasing:** versioning, building release binaries, installing the systemd
  units, generating `/etc/sudix/policy.toml` via `sudixd default-config`,
  enrolling TOTP via `sudixd enroll`, the config permission requirements
  (root-owned, not world-writable), and the security checklist (verify allowlist,
  verify UID roles, verify approval method matches the deployment's human
  presence model — esp. the disjoint-UID → TOTP rule from Step 2).
- Update README **Status** section: move completed items out of "Known gaps."
- Fix the stale README line "The starter allowlist and hard denylist live in
  `src/bin/sudixd.rs`" → now config-driven (`sudixd default-config`).

**Tests to add:** none (docs). Verify links resolve and code snippets are
accurate against the shipped flags/subcommands.

---

## Final cleanup (when the whole plan lands)

- Delete `NEXT_STEPS.md` — its content is now implemented and documented.
- **Delete this plan file** (`docs/PLAN-production-hardening.md`). Plans are
  ephemeral and must never be referenced by code or shipped docs.
- Confirm `just prep` is green and the README reflects reality.

## Open risks / where to stop and ask

- **Step 8 socket activation vs. `forbid(unsafe_code)`** — the one place the plan
  may hit a hard wall. If no crate offers safe fd adoption, defer socket
  activation (don't weaken the lint). Ask if unsure.
- **Step 5/6 merge** — if a stubbed `totp` approver leaves dead/broken code,
  land 5+6 as one commit.
- Any place a "locked decision" above proves unworkable: **stop and ask**, do
  not improvise a different security model.
