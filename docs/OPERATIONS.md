# sudix — Testing, Building, and Releasing

## Toolchain

- **Rust:** `rust-version = "1.95"` (edition 2024)
- **System tools:** `zenity` at runtime (for `method = "agent"`, run inside the graphical session by `sudix-agent`); not needed at build time.
- **`just`:** the `justfile` provides the standard recipes.

## Building

```sh
cargo build --release
# or via just:
just build
```

Produced binaries: `target/release/sudixd`, `target/release/sudix`, and `target/release/sudix-agent`.

## Testing

```sh
cargo test
# or:
just test
```

### What the tests cover

- **Unit tests** (`src/lib.rs`, `src/bin/sudix.rs`): all modules have inline
  `#[cfg(test)]` modules covering policy matching, config parsing/validation,
  scoping (cache hit/miss, TTL expiry, rate limiting), TOTP approval, cwd
  validation, protocol round-trips, client argument parsing, and the audit log.
- **Integration tests** (`tests/socket_roundtrip.rs`): drive a real broker
  over a real Unix socket. The test process is its own peer (kernel-vouched
  uid), exercising the full pipeline including SO_PEERCRED auth. Tests run
  unprivileged.
- **No root required:** all tests run as the current user. The peer-cred test
  uses `getuid()` so the authorized uid is the test runner's own uid.

### Testing the TOTP path

Generate a test secret and verify a code manually:

```sh
# In tests, TotpApprover is built directly with a known base32 secret
# (see approval::tests). For end-to-end TOTP testing:
sudo sudixd enroll          # writes /etc/sudix/totp.key, prints otpauth://
# Scan with an authenticator app, then:
sudix --otp <code> -- id
```

### Pre-commit gate

```sh
just prep   # runs: fmt, lint (clippy), machete (unused deps), build, test
```

All of `just prep` must pass before committing.

## Releasing

### 1. Build release binaries

```sh
cargo build --release
```

### 2. Install binaries

```sh
sudo install -o root -g root -m 755 target/release/sudixd /usr/bin/sudixd
sudo install -o root -g root -m 755 target/release/sudix  /usr/bin/sudix
```

### 3. Generate the policy config

```sh
sudo mkdir -p /etc/sudix
sudixd default-config | sudo tee /etc/sudix/policy.toml > /dev/null
sudo chown root:root /etc/sudix/policy.toml
sudo chmod 644 /etc/sudix/policy.toml   # 640 is also fine; never 666 or 664
```

Edit `/etc/sudix/policy.toml`:
- Set `agent_uids` to the uid(s) of the coding agent and the human approver (same uid for a single-user desktop).
- Set `approver_uids` to the same uid(s).
- Choose `method = "agent"` (desktop GUI via `sudix-agent`) or `method = "totp"` (headless).
- Adjust the `deny` and `allow` token-matcher arrays. See the README "Rule format" section for syntax
  (`"token"` = exact match, `{ re = "…" }` = anchored regex, `{ rest = true }` = trailing tokens).
- The daemon **hot-reloads** on each request when the file's **contents change** (SHA-256) — no
  `systemctl restart` needed after edits. Same-content saves are no-ops; the approval cache and
  rate-limit state survive reloads where the allow rules are unchanged. If the reload fails (bad TOML
  or invalid rule), that request is refused with an error and the old policy is kept in memory until
  the file is fixed.

**Security checklist:**
- Verify the allowlist covers only low-blast-radius commands.
- Verify `agent_uids` and `approver_uids` reflect the actual deployment.
- For headless/CI deployments, use `method = "totp"` and `sudo sudixd enroll`.
- Confirm the file is owned by root and not world-writable.

### 4. Enroll TOTP (headless deployments only)

```sh
# After setting totp_secret_path in /etc/sudix/policy.toml:
sudo sudixd enroll
# Prints an otpauth:// URI — scan with your authenticator app.
# Use --force to regenerate (invalidates existing enrolled devices).
```

### 5. Install systemd units

Install the system broker (runs as root, socket-activated):

```sh
sudo install -o root -g root -m 644 \
    dist/systemd/sudixd.service dist/systemd/sudixd.socket \
    /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sudixd.socket
```

Install the per-user approval agent (runs in the graphical session):

```sh
sudo install -o root -g root -m 644 \
    dist/systemd/sudix-agent.service \
    /usr/lib/systemd/user/
sudo install -o root -g root -m 644 \
    dist/systemd/90-sudix.preset \
    /usr/lib/systemd/user-preset/
```

The preset auto-enables `sudix-agent.service` for each user on their next
`systemctl --user preset` run (which happens automatically at package install
and first login on systems that run `systemd-sysusers`):

```sh
systemctl --user preset sudix-agent.service
systemctl --user start sudix-agent.service
systemctl --user is-enabled sudix-agent   # should print "enabled"
```

Verify the broker:

```sh
systemd-analyze verify /usr/lib/systemd/system/sudixd.service
systemctl status sudixd.socket
```

**Socket mode:** `sudixd.socket` uses `SocketMode=0666`. Authorization is
enforced by `SO_PEERCRED` (`cfg.agent_uids`), not by the socket's filesystem
permissions. The 0666 mode allows any user to attempt a connection; uids not
in `agent_uids` are refused immediately before policy is consulted. Tighten to
`0660` + `SocketGroup=sudix` if defense-in-depth at the filesystem level is
required for your threat model.

### 6. Install `sudix-agent` binary

```sh
sudo install -o root -g root -m 755 target/release/sudix-agent /usr/bin/sudix-agent
```

### 7. Smoke test

For `method = "agent"` (desktop):

```sh
sudix --help               # prints usage and exits 0
sudix -- id
# sudix-agent shows a zenity dialog; Allow → prints uid info, exit 0
#                                     Deny  → "sudix: denied: denied by user", exit 126
# No agent running → "sudix: error: no approval agent running …", exit 125
```

For `method = "totp"` (headless):

```sh
sudix --otp <code> -- id   # correct code → runs; wrong code → exit 126
```

**Exit codes:**
- `0` — command ran; exit code is forwarded from the subprocess.
- `125` — approver error (agent not running, spawn failure). Not a denial.
- `126` — explicitly denied by the approver (user clicked Deny or wrong TOTP code).

### Running without systemd

```sh
sudo SUDIX_RUNTIME_DIR=/run/sudix sudixd &
sudix-agent &   # run in the graphical session as the normal user
```

The daemon creates `/run/sudix/` if it doesn't exist and binds
`/run/sudix/sudixd.sock`. Audit log: `/run/sudix/audit.log`.

### The per-user approval agent (`sudix-agent`)

`sudix-agent` must run in the user's graphical session. It:

1. Connects to the broker socket (`$SUDIX_SOCKET`, default `/run/sudix/sudixd.sock`).
2. Registers as the approver for its uid via `Hello::RegisterAgent`.
3. Waits for `Prompt` messages from the broker and shows a `zenity` dialog for each.
4. Sends `Verdict::Allow` or `Verdict::Deny` (or `Verdict::Error` on spawn failure).
5. Reconnects with bounded backoff (1 s → 30 s) if the broker closes the connection.

The systemd user service (`WantedBy=graphical-session.target`) starts it
automatically when a graphical session opens. The preset (`90-sudix.preset`)
enables it without requiring user action after package install.

If `sudix-agent` is not running when a request arrives, the broker waits up to
10 seconds for it to register, then returns `Response::Error` — never a silent
denial.
