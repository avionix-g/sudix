# sudix — Testing, Building, and Releasing

## Toolchain

- **Rust:** `rust-version = "1.95"` (edition 2024)
- **System tools:** `zenity` at runtime (for `method = "zenity"`); not needed at build time.
- **`just`:** the `justfile` provides the standard recipes.

## Building

```sh
cargo build --release
# or via just:
just build
```

Produced binaries: `target/release/sudixd` and `target/release/sudix`.

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
- Set `agent_uids` to the uid(s) of the coding agent.
- Set `approver_uids` to the uid(s) of the human approver.
- Choose `method = "zenity"` (desktop) or `method = "totp"` (headless).
- Adjust the `[[allow]]` rules and `hard_deny` list.

**Security checklist:**
- Verify the allowlist covers only low-blast-radius commands.
- Verify `agent_uids` and `approver_uids` reflect the actual deployment.
- If sets are disjoint, `method = "totp"` is required (the daemon enforces this).
- Confirm the file is owned by root and not world-writable.

### 4. Enroll TOTP (headless deployments only)

```sh
# After setting totp_secret_path in /etc/sudix/policy.toml:
sudo sudixd enroll
# Prints an otpauth:// URI — scan with your authenticator app.
# Use --force to regenerate (invalidates existing enrolled devices).
```

### 5. Install systemd units

```sh
sudo install -o root -g root -m 644 \
    dist/systemd/sudixd.service dist/systemd/sudixd.socket \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sudixd.socket
```

Verify:

```sh
systemd-analyze verify /etc/systemd/system/sudixd.service
systemctl status sudixd.socket
```

### 6. Smoke test

```sh
sudix -- id
# Should prompt for approval (zenity) or request --otp (totp) and return uid info.
```

### Running without systemd

```sh
sudo SUDIX_RUNTIME_DIR=/run/sudix sudixd
```

The daemon creates `/run/sudix/` if it doesn't exist and binds
`/run/sudix/sudixd.sock`. Audit log: `/run/sudix/audit.log`.
