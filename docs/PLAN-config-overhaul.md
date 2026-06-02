# PLAN: Config overhaul — hot reload, regex rules, unified deny/allow, `--help`

## Intent

Four related changes to how `sudixd` is configured and how `sudix` is invoked:

1. **Hot-reload the policy.** Editing `/etc/sudix/policy.toml` should take effect
   without restarting the daemon. The daemon caches the config's mtime at startup
   and, on each incoming request, re-stats the file; if the mtime changed it
   reloads before evaluating the request. A reload that fails to load or validate
   **fails the current request closed** (returns an error to the caller) and leaves
   the previously-loaded config in place so the next request retries the reload.
   The daemon must never serve requests against a config it could not validate, and
   a bad edit must never silently widen authorization.

2. **Unify the rule structure.** Replace the two dissimilar knobs — `hard_deny`
   (program basenames) and `allow` (positional token patterns) — with two arrays of
   the *same* shape: `deny` and `allow`. **Deny takes precedence over allow** and is
   evaluated first. This makes the model symmetric and auditable, and makes a global
   "deny all" / "allow all" rule expressible (impossible today).

3. **Regex matching against a shell-quoted command rendering.** Each rule is an
   inline table `{ argv = "<regex>", ... }`. The regex is matched against a single
   string built from the request's argv:
   - `argv[0]` is normalized to its **basename** (preserving today's anti-path-spoofing
     property: `/usr/bin/pacman` ≡ `pacman`);
   - every token is **shell-quoted** (POSIX `sh` quoting via `shlex::try_quote`) and
     joined with single spaces.

   So `["rm", "-rf /"]` renders as `rm '-rf /'` and `["rm", "-rf", "/"]` renders as
   `rm -rf /` — distinct strings, so an argument containing a space cannot spoof a
   token boundary. This is the security-critical reason for quoting rather than a
   naive space-join.

   Patterns are **unanchored** by default; authors anchor with `^`/`$` as needed.
   `{ argv = ".*" }` is the "match everything" rule (allow-all or deny-all depending
   on which array it sits in). This unanchored-by-default behavior is a sharp edge and
   must be documented prominently in the generated config and OPERATIONS.md.

4. **`sudix -h` / `--help`.** Add a help flag to the `sudix` client that prints usage
   and exits 0.

### Decisions already made (do not re-litigate)

- Matching model: **single regex per rule against the basename-normalized, shell-quoted
  argv rendering.** Not per-token, not NUL-joined, not auto-anchored.
- Rule shape: both `deny` and `allow` are arrays of **inline tables**, e.g.
  `allow = [ { argv = "^id$" } ]`. Allow tables additionally carry the optional
  scoping knobs `cache_ttl_secs` and `rate_per_min` (unchanged semantics). Deny tables
  carry only `argv` (scoping is meaningless for denies).
- Reload failure policy: **fail the request closed** (`Response::Error`), keep the old
  config cached, retry on the next request.
- Regex engine: the `regex` crate (already present transitively in the lock tree; add
  it as an explicit workspace dependency).
- Shell quoting: the `shlex` crate.

### Non-goals

- No change to the approval pipeline, peer-cred auth, audit format, or protocol.
- No change to `sudix-agent`.
- No global rate-limit / TTL config; scoping stays per-allow-rule.
- No `inotify`/watch-based reload; mtime polling on each request is sufficient for this
  low-volume daemon and is simpler and race-tolerant.

---

## Overview (commit-by-commit)

1. **Add `regex` and `shlex` deps; implement the regex/shell-quote matching engine in `policy.rs`.**
2. **Rework the config schema to `deny`/`allow` inline-table arrays and update the starter config.**
3. **Make the daemon's policy hot-reloadable (mtime cache + per-request reload, fail-closed).**
4. **Add `-h`/`--help` to the `sudix` client.**
5. **Update docs (README, OPERATIONS.md).**

Each step is a single commit. Steps 1–2 are coupled (the schema change depends on the
new engine) but are kept separate so the engine lands with its own tests first; if that
proves awkward during implementation, they may be squashed — but only those two.

---

## Step 1 — Regex matching engine in `policy.rs`

**Commit title:** `Replace glob token rules with shell-quoted regex matching`

**Files to touch:**
- `Cargo.toml` (workspace `[workspace.dependencies]`): add `regex = "1"` and `shlex = "1"`.
- `crates/sudix/Cargo.toml`: depend on `regex` and `shlex`.
- `crates/sudix/src/policy.rs`.

**Logic to implement:**

Replace the token-array `Rule` and `Policy` with a regex-based design.

1. **Command rendering** — a free function, the single source of truth for what a regex
   sees. Make it `pub` so config validation and tests can call it:
   ```rust
   /// Render argv into the canonical string a policy regex is matched against:
   /// basename(argv[0]) + each token shell-quoted, space-joined.
   #[must_use]
   pub fn render_command(argv: &[String]) -> String
   ```
   - First token: `basename(argv[0])` then shell-quote the basename.
   - Remaining tokens: shell-quote each.
   - Join all quoted pieces with a single ASCII space.
   - Use `shlex::try_quote` (returns `Cow`). If quoting fails (only on interior NUL,
     which is impossible in a `String` argv from the protocol), fall back to the raw
     token — document this as unreachable-in-practice.
   - Keep the existing `basename()` helper.

   > Note: `shlex` quotes a token only when it contains shell-significant characters, so
   > ordinary tokens like `pacman`, `-S`, `ripgrep` render unquoted (`pacman -S ripgrep`),
   > which keeps regexes readable. Tokens with spaces/quotes/globs get quoted.

2. **`Rule`** wraps a compiled `regex::Regex`:
   ```rust
   pub struct Rule { re: Regex, src: String }
   impl Rule {
       /// Compile a rule regex. The pattern is used unanchored (author anchors).
       pub fn new(pattern: &str) -> Result<Self, String>  // err = regex compile error
       fn is_match(&self, rendered: &str) -> bool
   }
   ```
   - Compile with `Regex::new`. On error return the regex error string (config
     validation will prefix it with the rule index).
   - Keep `src` (the original pattern) for error messages / debugging.
   - `is_match` uses `regex::Regex::is_match` against the rendered command.

3. **`Policy`** holds two ordered `Vec<Rule>`:
   ```rust
   pub struct Policy { deny: Vec<Rule>, allow: Vec<Rule> }
   impl Policy {
       pub fn new(deny: Vec<Rule>, allow: Vec<Rule>) -> Self
       pub fn evaluate(&self, argv: &[String]) -> Verdict
   }
   ```
   `evaluate`:
   - Empty argv → `Denied { reason: "empty argv" }` (unchanged).
   - Render the command once via `render_command`.
   - **Deny first:** if any `deny` rule matches → `Denied { reason: format!("command matches deny rule") }`.
     (Reason text need not name the rule; keep it generic and caller-safe. Optionally
     include the matched rule's `src` for the audit/local log — but the response `why`
     stays generic.)
   - **Then allow:** first matching `allow` rule index → `Allowed { rule_index }`.
   - No match → `Denied { reason: "command does not match any allow rule" }`.

   `Verdict` is unchanged (`Allowed { rule_index }` / `Denied { reason }`). `rule_index`
   remains the 0-based index into the **allow** array (deny rules are not indexed; they
   never reach scoping).

**Tests to add/port** (in `policy.rs`):
- `render_command` cases: basename normalization (`/usr/bin/pacman -S rg` →
  `pacman -S rg`); space-containing arg is quoted (`["rm","-rf /"]` →
  `rm '-rf /'`); the two `rm` argv shapes render to *different* strings.
- Deny precedence: a command matching both an allow and a deny rule is `Denied`.
- Allow-all: `allow = [".*"]` allows an arbitrary command; deny-all: `deny = [".*"]`
  denies everything including otherwise-allowed commands.
- Anchoring: `^id$` matches `["id"]` but not `["id", "-u"]` (renders `id -u`); an
  unanchored `pacman -S ` matches `["pacman","-S","rg"]`.
- Path-spoofing still blocked: `/usr/bin/dd` denied by a `^dd` deny rule.
- Invalid regex → `Rule::new` returns `Err`.
- Port the spirit of the old positional tests where they still make sense (e.g.
  `systemctl status <one arg>` becomes a regex like `^systemctl status \S+$`).

---

## Step 2 — Config schema: `deny`/`allow` inline tables

**Commit title:** `Coalesce config into deny/allow regex rule arrays`

**Files to touch:**
- `crates/sudix/src/config.rs`.

**Logic to implement:**

1. **New entry types.** Replace `AllowEntry` and the `hard_deny: Vec<String>` field.
   ```rust
   #[derive(Debug, Clone, Deserialize)]
   #[serde(deny_unknown_fields)]
   pub struct DenyEntry {
       pub argv: String,
   }

   #[derive(Debug, Clone, Deserialize)]
   #[serde(deny_unknown_fields)]
   pub struct AllowEntry {
       pub argv: String,
       #[serde(default)]
       pub cache_ttl_secs: u64,
       #[serde(default)]
       pub rate_per_min: u32,
   }
   ```

2. **`FileConfig`** fields become:
   ```rust
   pub deny: Vec<DenyEntry>,    // was hard_deny: Vec<String>
   pub allow: Vec<AllowEntry>,  // shape changed: argv is now a String regex
   pub agent_uids: Vec<u32>,
   pub approver_uids: Vec<u32>,
   #[serde(default)] pub approval: ApprovalConfig,
   ```
   Add `#[serde(default)]` to `deny` so an absent `deny` array is an empty list
   (allow stays required, matching today where `allow` is required and `hard_deny` is
   required — but make `deny` optional since "no extra denies" is a sane, safe default
   given deny-by-default still holds via the allowlist). Keep `allow` required.

3. **`validate`:**
   - Compile every `deny[i].argv` and `allow[i].argv` via `Rule::new`, mapping errors to
     `ConfigError::Invalid(format!("deny rule {i}: {e}"))` / `"allow rule {i}: {e}"`.
   - Keep the `agent_uids` / `approver_uids` non-empty checks and the
     `totp` ⇒ `totp_secret_path` check unchanged.

4. **`build_policy`:** compile both arrays into `Policy::new(deny_rules, allow_rules)`.
   Keep the `expect("already validated")` invariant (validate guarantees compilation).

5. **`rule_scoping`:** unchanged signature (`Vec<(u64, u32)>`), now reads
   `cache_ttl_secs`/`rate_per_min` off the new `AllowEntry`.

6. **`default_config_toml`:** rewrite to the new schema. It must reproduce the previous
   *effective* policy as closely as the new model allows. Concretely:
   ```toml
   # sudix policy — generated by `sudixd default-config`
   #
   # This file must be owned by root and not group- or world-writable.
   #   sudo chown root:root /etc/sudix/policy.toml
   #   sudo chmod 644 /etc/sudix/policy.toml   # or 640; not 666/664
   #
   # Rules match a REGEX (Rust `regex` crate syntax) against a rendered command
   # string: argv[0] is reduced to its basename, every token is shell-quoted, and
   # the tokens are joined with single spaces. Example renderings:
   #   /usr/bin/pacman -S ripgrep   ->  pacman -S ripgrep
   #   rm "-rf /"                    ->  rm '-rf /'
   #
   # Patterns are UNANCHORED: `id` also matches `id -u` (renders "id -u").
   # Anchor with ^ and $ to match an exact command, e.g. "^id$".
   # `.*` matches everything — use it for an explicit allow-all or deny-all.
   #
   # deny is checked first and OVERRIDES allow.

   # Programs/commands refused regardless of allow rules.
   deny = [
     { argv = "^(sh|bash|zsh|fish)( |$)" },
     { argv = "^(dd|mkfs|fdisk|parted)( |$)" },
     { argv = "^(tee|chmod|chown)( |$)" },
     { argv = "^(visudo|su|sudo)( |$)" },
     { argv = "^env( |$)" },
     { argv = "^(vi|vim|nano)( |$)" },
     { argv = "^(python|perl)( |$)" },
   ]

   # Replace 1000 with the uid(s) of the agent and the human approver.
   agent_uids    = [1000]
   approver_uids = [1000]

   [approval]
   # "agent" (per-user sudix-agent in the graphical session) or "totp" (headless).
   method = "agent"
   # totp_secret_path = "/etc/sudix/totp.key"   # required when method = "totp"

   # Allow rules. Optional per-rule scoping (both default to 0 = off):
   #   cache_ttl_secs = 300   # auto-approve identical argv for N seconds after one approval
   #   rate_per_min   = 10    # max executions/min; over limit → denied
   allow = [
     { argv = "^pacman -S " },
     { argv = "^pacman -Syu( |$)" },
     { argv = "^systemctl status \\S+$" },
     { argv = "^systemctl restart \\S+$" },
     { argv = "^id$" },
   ]
   ```
   > Implementer note: the `deny` patterns intentionally use `( |$)` after the program
   > name so `^bash` does not also deny e.g. `bashfoo`; they match `bash` alone or
   > `bash <args>`. Verify each compiles and that the test below passes.

**Tests to update/add** (in `config.rs`):
- Rewrite every existing test that uses `hard_deny = [...]` / `argv = [array]` to the new
  `deny = [ { argv = "..." } ]` / `allow = [ { argv = "..." } ]` shape.
- `default_config_parses_and_matches_old_policy`: keep the asserted behaviors —
  `pacman -S rg` allowed, `id` allowed, `bash -c ...` denied, `rm -rf /` denied (not on
  allowlist). Update inputs to argv vecs as before.
- `round_trip_allow_deny`: port to new schema; assert deny-over-allow precedence with a
  rule present in both arrays.
- Add: invalid regex in a `deny`/`allow` entry → `ConfigError::Invalid` containing
  `"deny rule 0"` / `"allow rule 0"`.
- Add: `deny = [ { argv = ".*" } ]` denies an otherwise-allowed command.
- Keep `unknown_key_is_a_parse_error` (now e.g. a stray key inside an inline table, since
  `deny_unknown_fields` applies to the entry tables too).
- Keep the perm-check, totp, and method-parsing tests; update their config bodies to the
  new schema (they mostly set `deny`/`allow` to small arrays).

---

## Step 3 — Hot-reload the daemon policy

**Commit title:** `Hot-reload policy.toml on config mtime change`

**Files to touch:**
- `crates/sudix/src/config.rs` (add an mtime helper).
- `crates/sudix/src/server.rs` (reloadable config holder + per-request reload).
- `crates/sudix/src/bin/sudixd.rs` (build the reloadable holder).

**Design:**

The daemon currently builds one immutable `server::Config`, clones it into an `Arc`, and
shares it across connection threads. Hot reload requires the policy-derived parts to be
swappable at runtime. Split `Config` into an **immutable** part (set once at startup) and
a **reloadable** part (rebuilt from the file on mtime change).

1. **`config.rs`:** add
   ```rust
   /// mtime of `path` as the value to compare across reloads. Returns the
   /// modified time; on platforms/files where mtime is unavailable, callers treat
   /// an error as "cannot determine — do not reload".
   pub fn config_mtime(path: &Path) -> std::io::Result<std::time::SystemTime>
   ```
   (Just `metadata(path)?.modified()`.)

2. **`server.rs`** — introduce a reloadable holder:
   ```rust
   /// The parts of the runtime config that a reload can change.
   #[derive(Clone)]
   pub struct PolicyBundle {
       pub policy: Policy,
       pub rule_scopes: Vec<RuleScope>,
       pub agent_uids: Vec<u32>,
   }

   /// Everything needed to reload: the file path + how to enforce perms.
   pub struct ReloadCtx {
       pub config_path: PathBuf,
       pub enforce_perms: bool,           // false only in tests
   }

   pub struct Config {
       pub socket_path: PathBuf,
       pub audit_path: PathBuf,
       pub reload: ReloadCtx,
       /// Current policy bundle behind an RwLock; swapped on reload.
       pub current: RwLock<PolicyBundle>,
       /// Last-seen config mtime; updated on successful reload.
       pub last_mtime: Mutex<Option<SystemTime>>,
   }
   ```
   - `agent_uids` moves into `PolicyBundle` so a reload can change the authorized uid set
     too (it lives in the same file and there's no reason to require a restart for it).
     **Peer-cred auth must read `agent_uids` from the current bundle**, not a startup copy.
   - Use `std::sync::RwLock` (dep-free). Reads are short; the daemon is low-volume.
   - `Config` is no longer `Clone` (it owns locks). Update `serve_on_with_registry_inner`
     to take `Arc<Config>` directly instead of cloning. Trace and fix all
     `Arc::new(cfg.clone())` / `Config { .. }` construction sites accordingly.

3. **Reload entry point** (free fn in `server.rs`):
   ```rust
   /// Reload the policy bundle from disk if the file's mtime changed since the last
   /// successful load. On success, swaps in the new bundle and clears approval state
   /// (rule indices may have shifted). On failure, leaves the current bundle intact
   /// and returns the error so the caller can fail the request closed.
   fn maybe_reload(cfg: &Config, state: &Mutex<ApprovalState>) -> Result<(), ConfigError>
   ```
   Logic:
   - `let m = config_mtime(&cfg.reload.config_path)`. If the stat itself errors, treat as
     a reload failure (return `Err`) — a vanished/unreadable config must not be served
     against stale state silently; fail the request closed.
   - Compare against `*cfg.last_mtime.lock()`. If unchanged (`Some(prev) == Some(m)`),
     return `Ok(())` (fast path, no reload).
   - If changed (or previously `None`): `FileConfig::load_with_checks(path, enforce_perms)`.
     - On `Ok(fc)`: build a new `PolicyBundle` (`policy = fc.build_policy()`,
       `rule_scopes` from `fc.rule_scoping()`, `agent_uids = fc.agent_uids`). Acquire the
       `current` write lock and replace it; **clear `ApprovalState`** (reset cache + rate
       maps — add a `ApprovalState::clear(&self_mut)` or just `*guard = ApprovalState::new()`)
       because cached `rule_index` keys are no longer valid against the new allow order;
       update `last_mtime` to `Some(m)`. Log `eprintln!("sudixd: reloaded policy from {}", ...)`.
       Return `Ok(())`.
     - On `Err(e)`: **do not** update `last_mtime`, **do not** swap. Log
       `eprintln!("sudixd: config reload failed, keeping previous policy: {e}")`. Return
       `Err(e)`.

   > mtime-not-updated-on-failure is deliberate: it means a still-broken file is retried on
   > every subsequent request until it's fixed, rather than being marked "seen". That keeps
   > requests failing closed until the operator fixes the file.

4. **Wire into the request path.** In `handle_connection_threaded`, **before** evaluating
   the request (and before the `agent_uids` peer-cred check, so a reload can update the uid
   set), call `maybe_reload`:
   - On `Err`, respond `Response::Error { why: "config reload failed; request refused".into() }`
     and return. Audit this as a new outcome (see below) or reuse `ApproverError`-style
     best-effort logging — prefer a dedicated outcome.
   - On `Ok`, take a read snapshot of the current bundle to pass into `handle_request`.

   **`handle_request` signature change:** it currently reads `cfg.policy`,
   `cfg.rule_scopes`, `cfg.agent_uids`. Change it to take the resolved
   `&PolicyBundle` (snapshot) for those, plus `cfg` for `audit_path`. Concretely, pass a
   `bundle: &PolicyBundle` parameter and read policy/scopes from it; keep `cfg` for
   `audit_path` only. Update all call sites and tests.

   > Snapshot semantics: clone the `PolicyBundle` out of the `RwLock` (or hold an `Arc`
   > inside the lock and clone the `Arc`). Cloning the bundle per request is cheap at this
   > volume; prefer storing `RwLock<Arc<PolicyBundle>>` and cloning the `Arc` to avoid
   > recompiling regexes. **Recommended: `RwLock<Arc<PolicyBundle>>`.** Adjust the struct
   > above accordingly (`current: RwLock<Arc<PolicyBundle>>`).

5. **`peer_uid` / auth:** read `agent_uids` from the snapshot bundle obtained after
   `maybe_reload`, not from a startup field.

6. **`bin/sudixd.rs`:** build the initial `PolicyBundle` from `file_cfg`, capture the
   initial mtime (`config_mtime(path)?`, store as `Some`), and construct the new `Config`
   with `RwLock::new(Arc::new(bundle))`, `last_mtime: Mutex::new(Some(initial_mtime))`,
   and `reload: ReloadCtx { config_path, enforce_perms: true }`. Pass `Arc<Config>` into
   the serve functions. The serve functions' signatures change from `&Config` to
   `Arc<Config>` (or `&Arc<Config>`); update `serve`, `serve_on`, `serve_with_registry`,
   `serve_on_with_registry`, and the `_inner`.

   > The static-vs-agent approver branching in `run_daemon` is unchanged; only how `cfg`
   > is built and passed changes.

**Tests to add** (in `server.rs`, using `enforce_perms = false` and a tempfile):
- **Reload picks up a new allow rule.** Write a config allowing `echo`, build `Config`,
  fire a request for a newly-allowed command → denied; rewrite the file (allowing it) and
  bump mtime; fire again → allowed. (To force a distinct mtime in a fast test, set the
  file's mtime explicitly via `filetime`-style `set_file_mtime` *or* sleep is not allowed
  — instead expose `maybe_reload` to tests and, if mtime granularity is a problem, have
  the test write then explicitly set a later mtime using `std::fs` + a helper. If a
  filetime dep is undesirable, the test can set `last_mtime` to `None` to force a reload.)
  **Implementer: prefer forcing reload by seeding `last_mtime = None` or by setting an
  explicitly older stored mtime, to keep the test deterministic without a sleep or new dep.**
- **Reload failure fails closed and keeps old policy.** Start with a valid config (allows
  `echo`). Overwrite the file with invalid TOML (or an uncompilable regex) and force an
  mtime change. A request → `Response::Error`; then fix the file → request allowed again.
  Assert the approver was never consulted on the failed-reload request.
- **No mtime change → no reload** (fast path): seed a bundle that denies everything, set
  `last_mtime` to the file's current mtime, point the file at a config that would allow —
  request is still denied because the fast path skips the reload. (This proves we don't
  reload spuriously.)
- **ApprovalState cleared on reload:** prime a cache hit under the old policy, trigger a
  reload, assert the next identical request prompts again (cache miss).
- Update the existing `test_cfg` helper and all `handle_request` call sites for the new
  signature (`bundle` param + `Arc<Config>`).

---

## Step 4 — `sudix -h` / `--help`

**Commit title:** `Add -h/--help to the sudix client`

**Files to touch:**
- `crates/sudix/src/bin/sudix.rs`.

**Logic to implement:**

1. Introduce a help path. Cleanest: have `parse_args` recognize `-h`/`--help` as the
   first/leading flag and return a distinct signal. Two options — pick the simpler:
   - Add a `help: bool` to `Args` and short-circuit in `run`; **or**
   - Make `parse_args` return `Result<Option<Args>, String>` where `None` means "help
     requested" (and `run`/`main` print usage + exit 0).

   **Recommended:** keep `parse_args` returning `Args` and instead detect `-h`/`--help`
   in the leading-flag loop by returning a sentinel error is *wrong* (help is not an
   error). Use the `Option<Args>` approach: `Ok(None)` ⇒ print help to stdout, exit 0.

2. `-h`/`--help` is only treated as the help flag when it appears **before** the command
   (same position rule as `--reason`/`--otp`): once the command starts, `-h` belongs to
   the command. Place the match arm alongside `--reason`/`--otp`.

3. Help text (print to **stdout**, exit **0**):
   ```
   sudix — request privileged command execution via the sudix broker.

   Usage:
       sudix [--reason TEXT] [--otp CODE] [--] <command> [args...]
       sudix -h | --help

   Options:
       --reason TEXT   Human-readable justification shown to the approver.
       --otp CODE      One-time code (when the broker uses TOTP approval).
       -h, --help      Show this help and exit.

   The command after `--` (or the first non-flag token) is submitted to the
   broker, which gates it through policy + human approval and, if approved,
   runs it as root and relays its output and exit code.

   Environment:
       SUDIX_SOCKET    Broker socket path (default: /run/sudix/sudixd.sock).
   ```
   Keep wording in sync with the module doc-comment.

**Tests to add** (in `sudix.rs`):
- `-h` as leading flag → `parse_args` returns the help signal (`Ok(None)`).
- `--help` likewise.
- `--help` *after* `--` (or after the command starts) is part of the command argv
  (e.g. `["--", "myapp", "--help"]` → argv `["myapp", "--help"]`, not help).
- Existing arg-parsing tests updated for the new return type.

---

## Step 5 — Docs

**Commit title:** `Document regex rules and config hot-reload`

**Files to touch:**
- `README.md`
- `docs/OPERATIONS.md`

**Logic to implement:**
- README "Configuration" section: replace the `hard_deny` + `[[allow]]` description with
  the `deny`/`allow` inline-table arrays, the regex/shell-quoted rendering rules, the
  **unanchored-by-default** caveat, and the allow-all/deny-all `.*` idiom. Update the
  `policy` row in the crate table ("Allowlist matching (`*` = one arg…)" → regex match).
- README/OPERATIONS: document **hot reload** — edits to `policy.toml` take effect on the
  next request; a config that fails to load causes requests to be **refused** (error)
  until fixed, and the daemon keeps serving the last-good config is *not* what happens —
  be precise: requests fail closed on reload error, the old in-memory policy is retained
  but **not used** for the failing request. State that `systemctl restart` is no longer
  required for policy edits.
- OPERATIONS: update the "Adjust the `[[allow]]` rules and `hard_deny` list" line and the
  exit-code/flow notes if they reference the old schema.
- Mention `sudix --help` where client usage is described.

---

## Cross-cutting verification (run before declaring each step done)

- `cargo build` and `cargo test -p sudix` green.
- `cargo clippy` clean (the workspace denies `pedantic`/`complexity`/etc.).
- `cargo run --bin sudixd -- default-config` prints a config that
  `FileConfig::load_with_checks(_, false)` accepts and whose `build_policy()` passes the
  behavioral assertions in Step 2.
- `sudix --help` prints usage and exits 0; `sudix -h` likewise.

## Open risks / notes for the implementer

- **Regex DoS:** the `regex` crate has linear-time guarantees (no catastrophic
  backtracking), so untrusted-author patterns are acceptable here; the config is
  root-owned anyway. No `RegexBuilder` size limit change needed, but do not switch to a
  backtracking engine.
- **`rule_index` stability across reload** is handled by clearing `ApprovalState` on every
  successful swap (Step 3). Do not try to remap indices.
- **mtime granularity in tests** — do not `sleep` to force a distinct mtime; force reloads
  by seeding `last_mtime = None` or an explicitly older `SystemTime`. Keep tests
  deterministic and dependency-free.
- If splitting `agent_uids` into the reloadable bundle proves to ripple too far, it is
  acceptable to keep `agent_uids` immutable at startup for this iteration **only if** you
  note it in the commit message — but the preferred design reloads it.
