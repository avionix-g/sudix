# PLAN: Per-user approval agent; distinguish errors from denials

## Intent

Two defects surfaced after install:

1. **Internal failures masquerade as user denials.** `Approver::approve` returns a bare `bool`
   (`crates/sudix/src/approval.rs`). `ZenityApprover` collapses *spawn failure*, *no display*,
   and *user clicked Deny* into one `false`. The server then always reports
   `Denied { why: "denied by user" }`. The user saw `sudix: denied: denied by user` when zenity
   had actually failed with "Failed to open display". **An error must report what actually
   happened, not a fake denial.**

2. **A root system daemon cannot draw a GUI dialog.** `sudixd` runs as root in the *system*
   manager via socket activation. The user's GUI lives in a per-user session
   (`$DISPLAY`/`$WAYLAND_DISPLAY`, session bus) the system daemon has no handle to, so `zenity`
   spawned from `sudixd` always fails. This is architectural.

**Decisions (locked):**

- Introduce a **per-user approval agent** (`sudix-agent`) that runs in the graphical session and
  shows the dialog. The broker routes each approval to the registered agent for the caller's uid
  and waits for the verdict.
- **Topology:** the agent connects to the existing broker socket (`/run/sudix/sudixd.sock`),
  registers as approver for its (kernel-vouched) uid, and holds the connection open. The broker
  keeps a `uid → agent connection` registry and routes prompts over it. Reuses the existing
  `peer_uid()` (`SO_PEERCRED`) authentication.
- **Lifecycle / UX:** `sudix-agent` ships as a systemd **user** service,
  `WantedBy=graphical-session.target`, **enabled by package preset**, so logging into the desktop
  auto-starts it with zero user management.
- **No-agent case:** the broker waits a short bounded time for an agent to register (covers the
  login race); if none appears it returns a **precise, actionable error** — never a denial.
- **Config:** remove the broken in-daemon `zenity` method; add an `agent` method. `totp` is
  unchanged and remains the headless path.
- **Approver result becomes 3-state** (`Allowed` / `Denied` / `Error`) end to end, with a new
  `Response::Error` and a distinct client exit code, so callers can tell "refused" from
  "couldn't decide".

Authorization is by peer credential (`cfg.agent_uids`), never by socket mode. For this plan the
same `agent_uids` set authorizes both command callers and registering agents.

## Overview (steps = commits)

1. Make the approver result 3-state and add `Response::Error`; fix the client message.
2. Add the connection-role + agent prompt/verdict protocol messages.
3. Add the broker-side agent registry and route approvals through it (`AgentApprover`).
4. Add the `sudix-agent` binary.
5. Config + systemd user service + preset + docs.

Each step must build and pass `cargo test -p sudix` and `cargo clippy --all-targets` before the
next begins.

---

## Step 1 — 3-state approval result; `Response::Error`; client error path

**Commit title:** `Distinguish approver errors from user denials`

**Files:**
- `crates/sudix/src/approval.rs`
- `crates/sudix/src/protocol.rs`
- `crates/sudix/src/server.rs`
- `crates/sudix/src/audit.rs`
- `crates/sudix/src/bin/sudix.rs`

**Logic:**
- In `approval.rs`, add:
  ```rust
  pub enum Approval { Allowed, Denied, Error(String) }
  ```
  Change the trait: `fn approve(&self, caller_uid: u32, req: &Request) -> Approval;`
  (the uid is needed in Step 3; thread it through now). Keep `clone_box`.
- `TotpApprover::approve` (`approval.rs`): map missing/wrong/replayed code → `Approval::Denied`;
  preserve the replay logic. (No `Error` cases today.)
- `protocol.rs`: add a variant to `Response`:
  ```rust
  Error { why: String },
  ```
  serde tag stays `decision`; new tag value `error`. Update the doc comment.
- `audit.rs`: add `Outcome::ApproverError` with tag string `approver-error`; extend the doc
  comment and every match over `Outcome`.
- `server.rs` `handle_request`: the human-approval block now matches `Approval`:
  - `Allowed` → existing record-approval + execute path.
  - `Denied` → `Response::Denied { why: "denied by user" }`, audit `DeniedUser` (unchanged).
  - `Error(why)` → `Response::Error { why }`, audit `ApproverError`.
  Update the `approver.approve(req)` call site to pass `caller_uid`.
- `server.rs` other call sites & the test fake approver (search `fn approve(`) updated to the new
  signature/return type.
- `bin/sudix.rs` `run()`: add a `Response::Error { why }` arm → `eprintln!("sudix: error: {why}")`
  and return exit code `125` (distinct from `126` used for `Denied`).

**Tests:**
- `approval.rs` tests: fake approver and assertions move from `bool` to `Approval`.
- `protocol.rs` tests: round-trip `Response::Error`.
- `server.rs` tests: a fake approver returning `Approval::Error` yields `Response::Error` and
  audits `ApproverError`.

---

## Step 2 — connection-role + prompt/verdict protocol

**Commit title:** `Add agent registration and prompt/verdict protocol`

**Files:**
- `crates/sudix/src/protocol.rs`

**Logic:**
- The socket has historically done one `Request → Response` per connection. Two connection
  *roles* now share it, so the first line declares the role:
  ```rust
  #[serde(tag = "kind", rename_all = "snake_case")]
  pub enum Hello {
      Command(Request),   // existing one-shot command flow
      RegisterAgent,      // persistent approver registration; uid taken from SO_PEERCRED
  }
  ```
- Broker→agent prompt over the persistent connection:
  ```rust
  pub struct Prompt { pub argv: Vec<String>, pub cwd: String, pub reason: String }
  pub enum Verdict { Allow, Deny, Error { why: String } }  // serde tag "verdict"
  ```
- Give `Hello`, `Prompt`, `Verdict` the same `to_line`/`from_line` helpers as `Request`/`Response`.

**Tests:**
- Round-trip `Hello::Command(Request)`, `Hello::RegisterAgent`, `Prompt`, each `Verdict`.

*Note:* the `sudix` client must now send `Hello::Command(req)` instead of a bare `Request`. Make
that change here in `bin/sudix.rs` `run()` so the wire format stays consistent, and update
`tests/socket_roundtrip.rs` helpers accordingly.

---

## Step 3 — broker agent registry + `AgentApprover`

**Commit title:** `Route approvals to the registered per-user agent`

**Files:**
- `crates/sudix/src/server.rs`
- `crates/sudix/src/approval.rs`

**Logic:**
- New shared registry in `server.rs`:
  ```rust
  struct AgentHandle { /* owns the agent UnixStream + a Mutex to serialize round-trips */ }
  type AgentRegistry = Mutex<HashMap<u32, AgentHandle>>;
  ```
  Construct an `Arc<AgentRegistry>` in `serve_on` next to `state`/`approval_mutex`; clone into
  each worker thread.
- `handle_connection_threaded`: after `peer_uid`, read the first line as `Hello`:
  - `RegisterAgent`: require uid ∈ `cfg.agent_uids`; insert an `AgentHandle` for the uid (replace
    any stale one); then serve this connection as the agent channel — block reading until EOF /
    error; on exit remove the uid from the registry. (Holds the connection for the agent's
    lifetime.)
  - `Command(req)`: existing flow → `handle_request`.
- `AgentApprover` (in `approval.rs`) holds an `Arc<AgentRegistry>`. `approve(caller_uid, req)`:
  - Look up the agent for `caller_uid`; if absent, **wait** up to a bounded time (default ~10s,
    poll/condvar) for one to register.
  - If found: send `Prompt` (built from the policy-checked, canonicalized `argv`/`cwd` and
    `req.reason`), read `Verdict` with a per-prompt timeout, map
    `Allow→Allowed`, `Deny→Denied`, `Error{why}→Error(why)`. Connection drop / timeout →
    `Approval::Error("approval agent disconnected"/"timed out")`.
  - Still no agent after the wait → `Approval::Error("no approval agent running in your session; \
    is sudix-agent running?")`.
  - Serialize per-agent round-trips via the handle's mutex; the existing `approval_mutex` in
    `handle_request` still serializes globally.
- `approver_for` (`approval.rs`): remove the `Zenity` arm; add an `Agent` arm constructing
  `AgentApprover` from the shared registry. Because the registry lives in `serve_on`, either:
  (a) build the `AgentApprover` inside `serve_on` after the registry exists, or
  (b) have `approver_for` return a marker and `serve_on` inject the registry. **Pick (a)**: move
  agent-approver construction into `serve_on`/`serve`, and keep `approver_for` for `totp` only
  (or have it return an enum the server resolves). Document the chosen wiring in the commit.
- Remove `ZenityApprover` and its tests.

**Tests:**
- `approval.rs`: `AgentApprover` against an in-process fake registry (no real socket) — agent
  allows, agent denies, agent errors, no-agent→`Error` after the wait (use a short test timeout).
- `server.rs`: registration inserts/removes a uid; a command for a uid with no agent →
  `Response::Error`.

---

## Step 4 — `sudix-agent` binary

**Commit title:** `Add sudix-agent: in-session approval dialog`

**Files:**
- `crates/sudix/src/bin/sudix-agent.rs` (new)
- `crates/sudix/Cargo.toml` (`[[bin]]` entry)

**Logic:**
- Connect to `SUDIX_SOCKET` (default `/run/sudix/sudixd.sock`); send `Hello::RegisterAgent`.
- Loop: read `Prompt` → render text via the existing `approval::prompt_text` (move it so it takes
  the prompt fields, or reuse as-is on a reconstructed `Request`) → spawn zenity with the **exact
  flags currently in `ZenityApprover`** (`--question --no-markup --title=… --text=… --ok-label=Allow
  --cancel-label=Deny --default-cancel --width=500`). Map: exit 0 → `Verdict::Allow`; clean
  non-zero → `Verdict::Deny`; spawn failure / no display → `Verdict::Error { why }`.
- On broker disconnect, reconnect with bounded backoff.
- Keep it dependency-light; reuse `sudix` library types for the protocol.

**Tests:**
- Unit-test the zenity-exit→`Verdict` mapping via a seam (a function taking an exit status / spawn
  result), without spawning a real dialog. Full GUI path is covered by manual verification.

---

## Step 5 — config, systemd user service, preset, docs

**Commit title:** `Ship sudix-agent user service; switch approval method to agent`

**Files:**
- `crates/sudix/src/config.rs`
- `dist/systemd/sudix-agent.service` (new, user unit)
- `dist/systemd/90-sudix.preset` (new, user preset)
- `dist/systemd/sudixd.socket`, `dist/systemd/sudixd.service` (already modified in working tree)
- `README` / `docs/OPERATIONS.md`

**Logic:**
- `config.rs`: `ApprovalMethod` — remove `Zenity`, add `Agent` (`#[serde rename "agent"]`); keep
  `Totp`. Update `ApprovalConfig::default` and `default_config_toml()` to `agent`.
- New user unit `sudix-agent.service`:
  ```ini
  [Unit]
  Description=sudix per-user approval agent
  After=graphical-session.target
  PartOf=graphical-session.target

  [Service]
  ExecStart=/usr/bin/sudix-agent
  Restart=on-failure

  [Install]
  WantedBy=graphical-session.target
  ```
  Installed to `/usr/lib/systemd/user/`.
- New preset `90-sudix.preset` (installed to `/usr/lib/systemd/user-preset/`):
  ```
  enable sudix-agent.service
  ```
  so `systemctl --user preset` (package install / first login) enables it without user action.
- Keep `sudixd.socket` reachable by configured agent uids. **Decide and document** whether
  `SocketMode=0666` (current working-tree value) is retained or tightened — authz is purely
  peer-cred (`cfg.agent_uids`), so socket mode only governs who may *attempt* a connection. Record
  the decision in the commit message and `OPERATIONS.md`.
- Docs: describe the agent, the user service + preset (no manual enable needed), the `agent`
  config method, the new `error` outcome / exit code `125`, and the headless `totp` alternative.

**Tests:**
- `tests/socket_roundtrip.rs`: a fake agent registers over the socket, then a command for that
  uid is `Allow`ed / `Deny`ed end to end; and a no-agent command returns `Response::Error`
  (not `Denied`).
- `config.rs` tests: `agent` parses; `zenity` no longer parses (or maps to an error).

---

## Verification

1. `cargo build` — builds `sudixd`, `sudix`, `sudix-agent`.
2. `cargo test -p sudix` — unit + integration, including agent routing and error-vs-denial.
3. `cargo clippy --all-targets` clean.
4. Manual, in a graphical session:
   - Start `sudixd` (via socket unit) and `sudix-agent`.
   - `sudix -- id` → zenity dialog in-session; **Allow** runs `id` as root; **Deny** →
     `sudix: denied: denied by user` (exit 126).
   - Kill `sudix-agent`, run `sudix -- id` → after the brief wait,
     `sudix: error: no approval agent running in your session …` (exit 125) — confirms defect 1
     fixed: error ≠ denial.
5. Headless: `method = "totp"`, `sudix --otp <code> -- id` works; wrong code → denied; broker-side
   failure → error.
6. `systemctl --user preset sudix-agent.service && systemctl --user is-enabled sudix-agent` →
   `enabled`.

## Open items (resolve in-flight, record in commit messages)
- Same vs. split uid sets for command callers and registering agents (plan: same `agent_uids`).
- Exact bounded waits: agent-registration (~10s) and per-prompt timeout.
- Retain `SocketMode=0666` or tighten.
