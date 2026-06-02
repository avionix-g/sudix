# PLAN — Per-token policy matcher + SHA-256 reload + review cleanups

## Intent

The `config-overhaul` branch replaced the old closed token grammar (`*` =
one arg, `**` = trailing) with **arbitrary regex matched against a single
shell-quoted rendering of argv**. The review (`REVIEW-config-overhaul.md`)
found this shifts privilege-escalation risk onto operators:

- A flat regex is **unanchored by default**, so `deny = "rm"` also denies
  `confirm`, and `allow = "systemctl status"` also allows
  `systemctl status sshd extrajunk` (sev 5).
- Tokens are joined into one string, so a newline inside an argument lets a
  `.`-based deny rule under-match — a deny-bypass when deny is used to carve
  an exception out of a broad allow (sev 4).

Root cause: token boundaries and matcher structure are both smuggled into
string content, exactly the class of bug the gate exists to prevent.

**Fix: match per shell token.** A rule is an ordered list of token-matchers.
Each matcher matches exactly one token (or, for the tail marker, the rest).
A regex escape hatch is available *per token*, anchored to that token, so
no matcher can ever span a token boundary. This retires findings #1, #2, and
the empty-token spoofing concern *by construction* rather than by patching.

We keep regex's expressiveness (the reason the old grammar was abandoned —
no allow-all, no flexible arg matching) but confine it to a single token.

Two safety guards are added to `Policy::evaluate`:
1. **Control char in any request token → immediate `Denied`.** No gated
   command needs a raw newline/tab/NUL in argv; rejecting them kills the
   newline-injection vector regardless of matcher behavior.
2. **Empty tokens match only explicitly** — falls out of per-token length
   matching plus anchored regex (`\S+` rejects empty); no special-casing.

Separately, the change-detector for hot-reload moves from **mtime to SHA-256
of file contents** (review #3): mtime misses same-mtime restores (`cp -p`,
backups) and causes spurious refusals during atomic-rename saves.

The remaining review findings (#4–#8 and the sev-1 notes) are folded in as
their own steps.

### The matcher model (locked)

A rule's `argv` is a TOML **array**. Each element is one of:

| TOML form          | Matcher        | Matches                                            |
|--------------------|----------------|----------------------------------------------------|
| bare string `"x"`  | `Literal`      | exactly one token, equal to `x` (byte-for-byte)    |
| `{ re = "…" }`     | `Regex`        | exactly one token, anchored `^(?:…)$`              |
| `{ rest = true }`  | `Rest`         | zero or more **trailing** tokens; final position only |

Rules (locked decisions):

- **Bare string is ALWAYS a literal.** There is no in-band sentinel. A literal
  `...` argument (e.g. some `cd` flavors) is just `"..."` and is unambiguous.
  `Rest` is the out-of-band table form `{ rest = true }`, a sibling of
  `{ re = … }`. This is the whole reason `Rest` is a table, not a string.
- **`argv[0]` (position 0) is basename-normalized before matching**, preserving
  the existing path-spoofing defense. A `Literal` or `Regex` at position 0
  matches the basename. (`Rest` at position 0 is allow-all; see below.)
- **Regex is anchored** to its token as `^(?:PATTERN)$` at compile time. The
  operator writes the inner pattern only; they cannot (and need not) add their
  own `^`/`$`. This removes the unanchored footgun entirely.
- **`Rest` is valid only as the final element.** Validated at load time
  (mirrors the old `**`-placement check). `Rest` in any non-final position is
  a config error.
- **Allow-all = `{ argv = [{ rest = true }] }`** — a lone `Rest`. It matches
  any **non-empty** argv (empty argv is already denied up front). Reads
  unambiguously as "anything".
- **Program-with-any-args** = `Rest` in the tail: `["pacman", "-S", { rest = true }]`.
- **Empty-token matching**: an empty token (`""` in argv) matches only an
  explicit empty `Literal` (`""`) or a `Regex` whose pattern accepts empty
  (e.g. `{ re = "" }` → `^(?:)$`). `\S+` and any non-empty literal reject it.
  This is automatic; no code special-cases empty.

### Matching algorithm (locked)

Given a rule `matchers: Vec<TokenMatcher>` and request `argv: &[String]`:

1. Caller has already guaranteed `argv` is non-empty and control-char-free
   (checked once in `evaluate`, not per rule).
2. Walk `matchers` and `argv` in lockstep by index `i`:
   - `Literal(s)`: require `i < argv.len()` and `effective(i) == s`. Else no match.
   - `Regex(re)`: require `i < argv.len()` and `re.is_match(effective(i))`.
     (`re` is pre-anchored, so `is_match` == full match of the token.) Else no match.
   - `Rest`: match succeeds immediately (consumes all remaining tokens,
     including none). Return true.
   where `effective(0) = basename(argv[0])`, `effective(i>0) = argv[i]`.
3. After consuming all matchers with no `Rest`: match iff `argv.len() ==
   matchers.len()` (every token consumed, none left over).

This is the old `match_args` shape generalized to a matcher enum. No
backtracking: `Rest` is final-only, so matching is a single linear pass.

### What this is NOT (scope guard)

- **No `one_of` / `any_of` sugar.** `{ re = "(status|restart)" }` covers it.
  Resisting sugar is how we avoid re-growing a bad regex grammar. Out of scope.
- **No per-matcher repetition** (`repeat = "*"`). `Rest`-in-the-middle is
  meaningless and reintroduces ambiguity. Out of scope.
- **`deny` and `allow` share the exact same matcher model.** A deny rule is
  just a `Rule` (list of matchers) with no scoping knobs.

---

## Overview

Ordered steps; each maps to one commit.

1. **Replace the regex-render engine with a per-token matcher in `policy.rs`.**
   New `TokenMatcher` enum, `Rule` as `Vec<TokenMatcher>`, anchored regex,
   control-char guard, actionable deny reason (review #4). Rewrite `policy.rs`
   tests.
2. **Update `config.rs` schema + validation for the token-array form.**
   `DenyEntry.argv` / `AllowEntry.argv` become `Vec<TokenMatcher>` via a
   string-or-table serde enum; `Rest`-placement validation; rewrite the default
   config TOML and `config.rs` tests. Restore `ConfigError::source()` (sev-1).
3. **Switch hot-reload from mtime to SHA-256 (review #3); preserve rate state
   on no-op-content reload (review #8); single-flight the reload (review #7).**
4. **Server cleanups (review #5, #6, sev-1 notes):** fix/strengthen the
   `no_mtime_change` test, dedupe `serve`/`serve_with_registry`, move
   `is_allowed` helper, shrink `handle_request` arg list.
5. **Docs:** rewrite README + OPERATIONS rule-format sections for the token
   model and SHA-256 reload.

Steps 1–2 must land together conceptually but are split so each commit
compiles and tests green. Step 1 leaves `config.rs` referencing the new
`Rule` API, so **step 1 and step 2 should be implemented back-to-back**; if
the implementer prefers, they may be squashed into one commit, but keep the
test rewrites attached to the step that introduces the API they test.

---

## Step 1 — Per-token matcher engine in `policy.rs`

**Commit title:** `Match policy rules per shell token instead of flat regex`

**Files:** `crates/sudix/src/policy.rs`

**References:** review #1, #2, #4; matcher model above.

### Logic

Replace the current `render_command` + flat-`Regex` `Rule` with a per-token
model.

1. **`TokenMatcher` enum** (new public type):
   ```rust
   pub enum TokenMatcher {
       Literal(String),
       Regex(Regex),   // pre-anchored ^(?:src)$
       Rest,
   }
   ```
   - It needs a manual `Debug` (Regex's Debug is noisy; print the source).
   - It needs `Clone` (Policy is Clone; Regex is Clone).
   - Store the original pattern string for `Regex` so deny reasons / Debug can
     show it. Either a struct variant `Regex { re: Regex, src: String }` or a
     small `CompiledRegex` newtype. Pick struct variant for simplicity.
   - **Constructor for the regex variant anchors the pattern:**
     `Regex::new(&format!("^(?:{pattern})$"))`. Anchoring is invisible to the
     operator. Return the compile error string on failure (as today).
   - Provide `TokenMatcher::literal(s)`, `TokenMatcher::regex(pattern) ->
     Result<Self, String>`, and a `Rest` constructor or just the variant.

2. **`Rule`** becomes an ordered matcher list:
   ```rust
   pub struct Rule { matchers: Vec<TokenMatcher> }
   ```
   - `Rule::new(matchers: Vec<TokenMatcher>) -> Result<Self, String>`:
     validates that `Rest`, if present, is the **final** element; error
     otherwise (`"`rest` is only valid as the final matcher`"`). Empty matcher
     list is an error (`"rule must have at least one matcher"`).
   - `Rule::is_match(&self, argv: &[String]) -> bool` implements the matching
     algorithm above. `argv[0]` basename-normalized via the existing
     `basename` fn; positions > 0 raw.
   - `Rule::describe(&self) -> String` for deny reasons: render the matcher
     list back to a readable form, e.g. `pacman -S {re:\S+} {rest}`. Used by
     `evaluate` to build the actionable deny reason (review #4).

3. **Delete `render_command`** and its tests entirely. There is no flat
   rendering anymore. (Grep the crate first: it is `pub`. Confirm no other
   module or integration test imports it — the review found only `policy.rs`
   internal use, but verify with `grep -rn render_command`.)

4. **`Policy::evaluate`** — new pipeline:
   ```
   1. argv empty                      → Denied { "empty argv" }
   2. any token has a control char    → Denied { "control character in argument" }
   3. first matching deny rule (find) → Denied { "denied by rule {i}: {describe}" }
   4. first matching allow rule       → Allowed { rule_index }
   5. otherwise                       → Denied { "no allow rule matched" }
   ```
   - Control-char check: a byte `< 0x20` or `== 0x7f` in any token. Helper
     `fn has_control_char(argv: &[String]) -> bool`. (NUL is impossible in a
     Rust `String`, but the check covers it for free; do not special-case.)
   - Deny: use `.iter().enumerate().find(...)` (not `any`) so the index and
     `describe()` are available for the reason (review #4). The constant
     `"command matches deny rule"` string is gone.
   - `Policy::new(deny: Vec<Rule>, allow: Vec<Rule>)` signature unchanged.

5. **Module docstring** (top of file): rewrite to describe per-token matching,
   the basename rule, anchored regex, `Rest`, and the control-char denial.
   Remove all mention of `render_command` / shell-quoting / "unanchored by
   default".

### Tests (rewrite `policy.rs` `mod tests` fully)

Keep `argv()` helper. Build a representative `policy()` using the new API:
deny `[dd]`, `[sh|bash via re]`; allow `pacman -S {rest}`, `systemctl status
{re:\S+}`, `id`.

Required cases (each a tiny `#[test]`):

- **Literal program match**: `["id"]` against rule `["id"]` → allowed;
  `["id","-u"]` → denied (length mismatch, no Rest).
- **Basename normalization**: `["/usr/bin/pacman","-S","rg"]` allowed;
  `["/usr/bin/dd",...]` denied by deny rule.
- **Rest tail**: `["pacman","-S","a","b"]` allowed; `["pacman","-S"]` allowed
  (Rest matches zero); `["pacman"]` denied (literal `-S` unmatched).
- **Allow-all** (`[Rest]` only): `["anything","goes"]` allowed; `[]` denied
  (empty argv guard fires first).
- **Per-token regex anchored**: rule `["systemctl","status",{re:\S+}]`:
  `["systemctl","status","sshd"]` allowed; `[...,"sshd","extra"]` denied
  (length); `["systemctl","status","a b"]` denied (token `a b` has a space,
  fails `\S+`). **Crucially:** `["systemctl","status","sshd"]` must NOT be
  matchable by smuggling — there is no flat string to smuggle into.
- **`rm`/`confirm` non-collision** (the headline fix): deny rule `["rm",{rest}]`
  does NOT deny `["confirm","x"]`. Assert allowed-or-default-denied but
  specifically that the *deny* did not fire (e.g. give `confirm` an allow rule
  and assert `Allowed`).
- **Control-char denial**: `["id\n-u"]` (or any token with `\n`) → Denied with
  reason containing "control character". Also `["echo","a\tb"]` denied.
- **Empty-token matching**: rule `["id"]` vs `["id",""]` → denied (length);
  rule `["echo",""]` vs `["echo",""]` → allowed (explicit empty literal);
  rule `["echo",{re:\S+}]` vs `["echo",""]` → denied (`\S+` rejects empty).
- **Rest placement validation**: `Rule::new` with `Rest` in non-final position
  → `Err`; `Rest` final → `Ok`; empty matcher list → `Err`.
- **Regex anchoring is implicit**: rule `["x",{re:foo}]` vs `["x","foobar"]`
  → denied (anchored, not prefix). vs `["x","foo"]` → allowed.
- **Deny reason is actionable**: a denied-by-deny verdict's `reason` contains
  the rule index and the `describe()` text (review #4).
- **rule_index correctness**: preserved from old tests — index reflects allow
  array position.
- **empty_argv_denied**, **deny_overrides_allow**: preserved.

Remove: all `render_*` tests, `invalid_regex_returns_err` (moves to the
`TokenMatcher::regex` constructor — keep a version asserting
`TokenMatcher::regex("(unclosed").is_err()`).

---

## Step 2 — Config schema + validation for token arrays

**Commit title:** `Parse deny/allow rules as per-token matcher arrays`

**Files:** `crates/sudix/src/config.rs`

**References:** review sev-1 (`ConfigError::source`); matcher model.

### Logic

1. **`TokenMatcher` deserialization.** `argv` in both `DenyEntry` and
   `AllowEntry` becomes `Vec<TokenMatcher>`. A TOML array element is either a
   string or a table. Implement via an untagged intermediate:
   ```rust
   #[derive(Deserialize)]
   #[serde(untagged)]
   enum RawMatcher {
       Literal(String),
       Table(RawTable),   // { re = "..." } xor { rest = true }
   }
   #[derive(Deserialize)]
   #[serde(deny_unknown_fields)]
   struct RawTable { re: Option<String>, rest: Option<bool> }
   ```
   Convert `RawMatcher` → `policy::TokenMatcher` in `validate`/`build`:
   - `Literal(s)` → `TokenMatcher::Literal(s)`.
   - `Table { re: Some(p), rest: None }` → `TokenMatcher::regex(&p)?`
     (compile + anchor; surface compile error with rule index).
   - `Table { rest: Some(true), re: None }` → `TokenMatcher::Rest`.
   - `Table { rest: Some(false) }` → error: `"rest = false is not meaningful"`.
   - Both `re` and `rest` set, or neither → error: `"matcher table needs
     exactly one of `re` or `rest`"`.
   Keep `RawMatcher` private to `config.rs`. Do NOT make `policy::TokenMatcher`
   itself `Deserialize` — keep the wire form and the engine type separate so
   the anchoring/validation lives in one place (`config.rs::validate`).

   `DenyEntry` keeps only `argv: Vec<RawMatcher>`. `AllowEntry` keeps
   `argv: Vec<RawMatcher>` + the existing `cache_ttl_secs` / `rate_per_min`.

2. **`validate()`**: for each deny and allow entry, convert its `RawMatcher`s
   to `TokenMatcher`s and call `Rule::new(...)`, mapping any error to
   `ConfigError::Invalid(format!("{deny|allow} rule {i}: {e}"))`. This catches
   bad regex, `rest`-not-final, empty rule, and the table-shape errors above.
   Keep the existing `agent_uids` / `approver_uids` / totp checks.

3. **`build_policy()`**: same conversion, `.expect("already validated")`.
   Factor the `RawMatcher -> Result<TokenMatcher>` conversion into one private
   helper used by both `validate` and `build_policy` (DRY — review-aligned).
   `rule_scoping()` unchanged.

4. **Restore `ConfigError::source()`** (review sev-1):
   ```rust
   impl std::error::Error for ConfigError {
       fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
           match self {
               Self::Io(e) => Some(e),
               Self::Parse(e) => Some(e),
               Self::Invalid(_) => None,
           }
       }
   }
   ```

5. **`default_config_toml()`**: rewrite for the token model. Comment block
   explains: bare string = exact token (argv[0] by basename); `{ re = "…" }`
   = one token, anchored automatically; `{ rest = true }` = the rest (final
   only); allow-all = `[{ rest = true }]`; deny is checked first. Replace every
   rule:
   ```toml
   deny = [
     { argv = [{ re = "sh|bash|zsh|fish" }, { rest = true }] },
     { argv = [{ re = "dd|mkfs|fdisk|parted" }, { rest = true }] },
     { argv = [{ re = "tee|chmod|chown" }, { rest = true }] },
     { argv = [{ re = "visudo|su|sudo" }, { rest = true }] },
     { argv = ["env", { rest = true }] },
     { argv = [{ re = "vi|vim|nano" }, { rest = true }] },
     { argv = [{ re = "python|perl" }, { rest = true }] },
   ]

   agent_uids    = [1000]
   approver_uids = [1000]

   allow = [
     { argv = ["pacman", "-S", { rest = true }] },
     { argv = ["pacman", "-Syu", { rest = true }] },
     { argv = ["systemctl", "status", { re = "\\S+" }] },
     { argv = ["systemctl", "restart", { re = "\\S+" }] },
     { argv = ["id"] },
   ]

   [approval]
   method = "agent"
   # totp_secret_path = "/etc/sudix/totp.key"
   ```
   Note the deny `re` for program names: position-0 matcher matches the
   basename, anchored `^(?:sh|bash|zsh|fish)$`, so `sh` matches but not
   `bashfoo`. The `{ rest = true }` lets any args follow. This is intentionally
   broader-then-`rest`; a bare `{ argv = [{ re = "sh|bash|zsh|fish" }] }`
   (no rest) would only deny the shell with *zero* args, which is wrong — keep
   `{ rest = true }`.

   **Note:** `pacman -S` with zero packages is now allowed again (Rest matches
   zero), restoring old-policy parity (review sev-1 `pacman -S` note). Good.

### Tests (rewrite `config.rs` `mod tests`)

Port every existing test to the new TOML form. Specifically:

- `round_trip_allow_deny`: token arrays; assert pacman/id allowed, dd/curl denied.
- `deny_overrides_allow_when_in_both`: `deny=[{argv=["id"]}]`, `allow=[{argv=["id"]}]` → denied.
- `invalid_deny_regex_is_config_error` / `invalid_allow_regex_is_config_error`:
  `{ re = "(unclosed" }` → `ConfigError::Invalid` with `"{deny|allow} rule 0"`.
- **New** `rest_not_final_is_config_error`:
  `allow = [{ argv = [{ rest = true }, "x"] }]` → Invalid, mentions rest.
- **New** `matcher_table_needs_exactly_one_key`:
  `{ argv = [{ re = "a", rest = true }] }` → Invalid; `{ argv = [{}] }` → Invalid.
- **New** `literal_dots_is_a_literal_not_rest`: a rule `{ argv = ["cd", "..."] }`
  loads, and `evaluate(["cd","..."])` is Allowed while `evaluate(["cd","x"])`
  is denied — proves `...` is a literal.
- **New** `allow_all_via_rest`: `allow = [{ argv = [{ rest = true }] }]`;
  `evaluate(["anything"])` allowed.
- `deny_all_denies_otherwise_allowed`: deny `[{rest=true}]` denies everything.
- `unknown_key_is_a_parse_error`, `missing_file_is_io_error`,
  `default_config_parses_and_matches_old_policy` (update expectations; add a
  `pacman -S` zero-package allowed assertion), approval-method tests,
  `perm_check_rejects_world_writable`: port TOML, keep assertions.

---

## Step 3 — SHA-256 reload, single-flight, rate-state preservation

**Commit title:** `Detect policy changes by content hash, not mtime`

**Files:** `crates/sudix/src/server.rs`, `crates/sudix/src/config.rs`,
`crates/sudix/Cargo.toml`, `Cargo.toml`

**References:** review #3, #7, #8.

### Logic

1. **Dependency:** add `sha2 = "0.10"` to workspace `Cargo.toml`
   `[workspace.dependencies]` and `crates/sudix/Cargo.toml` `[dependencies]`
   (`sha2.workspace = true`). (`sha2` is the standard, well-audited choice;
   change-detection doesn't strictly need crypto strength, but it's cheap and
   removes any "is this hash good enough" question.)

2. **`config.rs`:** replace `config_mtime` with
   ```rust
   /// SHA-256 of the config file's contents, for reload change-detection.
   /// # Errors
   /// Propagates any io::Error from reading the file.
   pub fn config_hash(path: &Path) -> std::io::Result<[u8; 32]>
   ```
   Read the whole file (`std::fs::read`), feed to `Sha256`, return the 32-byte
   digest. Reading the bytes (vs `stat`) is what closes the same-mtime hole;
   it also dodges the atomic-rename ENOENT race because a single `read`
   observes one complete inode.

   Delete `config_mtime`. Grep for callers (`grep -rn config_mtime crates/`).
   Confirmed call sites (all must switch to `config_hash` + the `initial_hash`
   field/param rename below):
   - `crates/sudix/src/bin/sudixd.rs` (1: `initial_mtime` at startup).
   - `crates/sudix/tests/socket_roundtrip.rs` (3 sites: `make_cfg` and two
     inline broker setups).
   - `crates/sudix/src/server.rs`: `maybe_reload` itself, the `Config::new`
     doc-comment, and the hot-reload **unit tests** (which seed/clear
     `last_mtime` directly — these become `last_hash`, and the test that reads
     `current_mtime` must read `config_hash` instead; see step 3 tests).

3. **`server.rs` `Config`:** rename `last_mtime: Mutex<Option<SystemTime>>`
   → `last_hash: Mutex<Option<[u8; 32]>>`. `Config::new`'s `initial_mtime:
   Option<SystemTime>` param → `initial_hash: Option<[u8; 32]>`. Drop the
   `use std::time::SystemTime`. `None` still means "force reload on first
   request".

4. **`maybe_reload` — single-flight + content hash (review #3, #7):**
   The current two-phase (read mtime, drop lock, reload, re-lock) lets two
   threads both reload. Replace with a single critical section over the hash
   check-and-store so only one thread reloads per change:
   ```
   fn maybe_reload(cfg, state) -> Result<(), ConfigError> {
       let h = config::config_hash(&cfg.reload.config_path)?;   // outside lock
       let mut last = cfg.last_hash.lock()...;                  // hold across swap
       if *last == Some(h) { return Ok(()); }                  // fast path
       match FileConfig::load_with_checks(path, enforce_perms) {
           Ok(fc) => {
               let new_bundle = Arc::new(bundle_from_file_cfg(&fc));
               // rate-state preservation: see step (5)
               swap cfg.current = new_bundle;
               reset-or-preserve approval state;
               *last = Some(h);
               eprintln!("sudixd: reloaded policy ...");
               Ok(())
           }
           Err(e) => { eprintln!("... keeping previous policy: {e}"); Err(e) }
       }
   }
   ```
   Holding `last_hash` across the load serializes reloaders. The hash read
   itself is outside the lock (cheap, no need to serialize stat/read). A second
   thread that blocked on the lock will, after the first finishes, see
   `*last == Some(h)` and take the fast path. **Lock-ordering note:** acquire
   `last_hash` before `current`/`state`; document it in a comment so future
   code keeps the order and avoids deadlock.

5. **Rate-state preservation on content-equal rule lists (review #8):**
   `ApprovalState` keys cache and rate by `rule_index`, so indices must be
   stable to keep state. Reload currently clears *all* state. New behavior:
   - Compute whether the **allow-rule list is structurally unchanged** across
     the reload. Cheapest robust signal: compare the new `FileConfig`'s allow
     entries to the old. But the old `FileConfig` isn't retained — only the
     bundle is. Two viable approaches:
     - **(A, preferred)** Add an `allow_fingerprint: u64` (or `[u8;32]`) to
       `PolicyBundle`, computed from the serialized allow rules + their scoping
       knobs at `bundle_from_file_cfg` time. On reload, if
       `new.allow_fingerprint == old.allow_fingerprint`, **preserve** the
       `ApprovalState` (indices and scoping identical → cache + rate still
       valid). Otherwise reset it (indices may have shifted).
     - (B) Always reset cache (argv-keyed, cheap to lose) but preserve rate
       only when fingerprints match. More code for little gain; prefer (A)'s
       single all-or-nothing decision.
   - Implement (A). The fingerprint covers allow `argv` matchers + `cache_ttl_secs`
     + `rate_per_min`, in order. Deny rules and uids do **not** affect it (they
     don't index `ApprovalState`).
   - When fingerprints differ → `*state.lock() = ApprovalState::new()` (current
     behavior). When equal → leave `state` untouched.
   - Update the `maybe_reload` doc-comment to state this precisely (replaces
     the vague "rule indices may have shifted").

### Tests (`server.rs` `mod tests`, hot-reload section)

- `reload_picks_up_new_allow_rule`: port to `config_hash`; force reload by
  setting `last_hash = None`. Assert new rule active.
- `reload_failure_fails_closed_and_keeps_old_policy`: port; break TOML, force
  reload, assert `Err` and old policy intact.
- **Rewrite** `no_mtime_change_skips_reload` → `same_content_skips_reload`
  (review #5): write config A, load, capture `config_hash(A)` into `last_hash`;
  overwrite the file with config B that allows `id`; call `maybe_reload`;
  assert `id` is **still denied** (skipped because... wait: hash differs now).
  **Correction:** to test the *skip*, the on-disk content must equal the stored
  hash. So: write A, seed `last_hash = config_hash(A)`, do NOT change the file,
  call `maybe_reload`, assert it returned `Ok` and the bundle is unchanged
  (e.g. a sentinel rule from A still present and a B-only rule absent). To
  prove the hash genuinely gates: a second assertion writes B, calls
  `maybe_reload` (now hash differs), asserts B's rule took effect. This is the
  honest version of the deleted rambling test — short, no narration.
- `approval_state_cleared_on_rule_change`: prime a cache entry; reload with a
  **different** allow list (force via `last_hash = None` + changed file);
  assert cache cleared.
- **New** `approval_state_preserved_on_identical_rules`: prime a cache entry;
  reload with byte-identical allow rules but a changed *deny* rule or comment
  (so file hash differs, allow fingerprint identical); assert the cache entry
  **survives** (rate/cache preserved). This is the review #8 regression guard.
- Remove the old `no_mtime_change_skips_reload` narration entirely.

---

## Step 4 — Server structural cleanups

**Commit title:** `Dedupe serve(); tidy handle_request and test helpers`

**Files:** `crates/sudix/src/server.rs`, `crates/sudix/src/policy.rs`

**References:** review #5 (done in step 3), #6, sev-1 (`is_allowed`,
`handle_request` args).

### Logic

1. **Dedupe `serve` / `serve_with_registry` (review #6).** Extract a private
   helper that does the shared work and returns the bound listener:
   ```rust
   fn bind_and_log(cfg: &Config) -> io::Result<UnixListener> {
       let agent_uids = {
           let b = cfg.current.read().unwrap_or_else(PoisonError::into_inner);
           b.agent_uids.clone()
       }; // guard dropped here, before any I/O
       let _stale = std::fs::remove_file(&cfg.socket_path);
       let listener = UnixListener::bind(&cfg.socket_path)?;
       restrict_socket_permissions(&cfg.socket_path)?;
       eprintln!("sudixd: listening on {} (agent uids: {:?})",
                 cfg.socket_path.display(), agent_uids);
       Ok(listener)
   }
   ```
   `serve` and `serve_with_registry` each become: `let l = bind_and_log(cfg)?;
   serve_on(cfg, &l, approver)` (resp. `serve_on_with_registry`). The
   read-lock is now scoped to the `agent_uids` clone and dropped before `bind`,
   fixing the "lock held across fallible I/O" smell. Remove the cosmetic outer
   blocks.

2. **`handle_request` arg count (review sev-1).** It takes both `cfg: &Config`
   and `bundle: &PolicyBundle` (8 args, `#[allow(clippy::too_many_arguments)]`).
   The bundle is a per-connection snapshot of `cfg.current`. Simplest reduction
   that stays clear: bundle the request-local pieces. Minimal change: pass
   `bundle` and keep `cfg` (audit path lives on `cfg`), but group the
   `(approver, approval_state, registry, clock, caller_uid)` plumbing is
   overkill for this step. **Do the cheap win only:** drop the
   `#[allow(clippy::too_many_arguments)]` by introducing a small
   `RequestCtx<'a>` struct holding `{ cfg: &Config, bundle: &PolicyBundle,
   caller_uid: u32 }` and pass `&RequestCtx` plus the approver/state/clock.
   If that balloons the diff, leave `handle_request` as-is and instead just
   remove the now-unneeded `#[allow(clippy::too_many_arguments)]` if clippy is
   satisfied — **verify with `cargo clippy`**. Do not over-engineer; the goal
   is "no clippy allow without cause," not a grand refactor. *(Implementer:
   pick the smaller diff that passes clippy clean.)*

3. **Move `is_allowed` helper (review sev-1).** The `#[cfg(test)] impl
   Verdict { fn is_allowed }` currently lives in `server.rs`. Move it to
   `policy.rs` under `#[cfg(test)]` next to `Verdict`, or — cleaner — make it a
   non-test `#[must_use] pub fn is_allowed(&self) -> bool` on `Verdict` in
   `policy.rs` (it's trivially useful and harmless in the public API). Prefer
   the public method; update the server test that uses it.

### Tests

No new behavior; existing tests must stay green. If `RequestCtx` is
introduced, update the `handle_request` call sites in the server unit tests
and the two integration-test brokers accordingly. Run the full suite +
clippy; both must be clean with no `too_many_arguments` allow remaining (or a
documented reason if one is genuinely unavoidable).

---

## Step 5 — Documentation

**Commit title:** `Document per-token rules and content-hash reload`

**Files:** `README.md`, `docs/OPERATIONS.md`

**References:** review #1 (docs are no longer the mitigation — the engine is —
but they must describe the new model), #3, #8.

### Logic

1. **README "Rule format" section** — replace the regex/shell-quoting prose:
   - A rule's `argv` is an ordered list of token-matchers.
   - bare string = one exact token (argv[0] by basename, so `/usr/bin/pacman`
     ≡ `pacman`).
   - `{ re = "…" }` = one token, matched by an **anchored** regex (you write
     the inner pattern; sudix anchors it — `\S+` matches one whitespace-free
     token).
   - `{ rest = true }` = zero or more trailing tokens; only valid last.
   - allow-all = `{ argv = [{ rest = true }] }`.
   - A literal `...` argument is just `"..."` — no special meaning.
   - deny is checked before allow; a deny match always wins.
   - Arguments containing control characters (newline/tab/etc.) are refused
     outright.
   - Update the architecture-table row for `policy` (currently "Regex matching
     against shell-quoted argv rendering") → "Per-token matching (literal /
     anchored-regex / rest). The policy gate."
   - Update the example config block to token arrays (mirror the new
     `default_config_toml`).

2. **README hot-reload paragraph + status list:** change "when the file's
   mtime changes" → "when the file's contents change (SHA-256)". Update the
   status bullet `Regex rules matched against shell-quoted...` →
   `Per-token rules: literal / anchored-regex / rest; deny takes precedence`.
   Add: editing the file preserves the approval cache and rate-limit state when
   the allow rules are unchanged (review #8); changing allow rules resets it.

3. **OPERATIONS.md:** the "Edit `/etc/sudix/policy.toml`" bullet about
   `deny`/`allow` regex arrays → token-matcher arrays, point to README. Update
   the hot-reload sentence: mtime → contents (SHA-256); note same-content saves
   are no-ops and rate state survives allow-unchanged edits. Keep the
   security-checklist items.

---

## Cross-cutting acceptance criteria

After all steps:

- `cargo build`, `cargo test` (unit + `socket_roundtrip` integration),
  `cargo clippy --all-targets` all clean. No `clippy::too_many_arguments`
  allow without a written justification.
- `grep -rn render_command` and `grep -rn config_mtime` return **nothing**
  (both removed).
- `sudixd default-config | <parse>` round-trips: a test loads
  `default_config_toml()` and asserts: `pacman -S rg` allowed, `pacman -S`
  (zero pkgs) allowed, `id` allowed, `bash -c ...` denied, `rm -rf /` denied,
  and `["id\n"]`-style control-char input denied.
- The `rm`/`confirm` non-collision and control-char denial each have a direct
  test (the two headline security fixes).
- No plan/TODO references left in code. Delete `docs/PLAN-token-matcher.md`
  and `REVIEW-config-overhaul.md` when the feature lands (per feature-plan
  workflow — plans and reviews are ephemeral).

## Notes for the implementer

- Steps 1 and 2 are tightly coupled (step 1 changes the `Rule` API that step 2
  feeds). Implement them in order; the tree need not compile *between* an
  unfinished step 1 and step 2, but each **commit** must compile and pass
  tests. If you cannot make step 1 compile without step 2's config changes,
  squash them into one commit titled per step 1 and note both in the body —
  do not leave a broken intermediate commit.
- `shlex` is no longer used by `policy.rs`. After step 1, grep for other
  `shlex` users (`grep -rn shlex`). If none remain, remove `shlex` from both
  Cargo manifests in step 1's commit. (Review noted shlex was added for
  `render_command`; it is likely the only user.)
- The `regex` dependency stays — it's now used per-token.
- When in doubt about a matcher edge case, the locked rules in **Intent →
  matcher model / matching algorithm** are authoritative. If a case isn't
  covered there, stop and ask rather than guessing.
```
