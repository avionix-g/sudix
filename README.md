# sudix

A privileged-action broker for coding agents.

## Problem

A coding agent running under your user account sometimes needs root. The usual
options all hand it more than you want:

- `NOPASSWD` sudoers → unattended, unbounded root.
- A stored password → after one approval the agent holds a reusable root
  credential, and the checks guarding it (cwd, parent-process name, env vars)
  are forgeable *by the agent*.

## Approach

`sudix` does not give the agent a credential. The agent **requests** a specific
command; a root daemon decides:

1. **Policy** (deny-by-default regex allowlist with an explicit deny list) —
   runs server-side, so the agent can't forge it. Denied requests never reach
   the human.
2. **Approval** — out-of-band (zenity dialog or TOTP code), showing the *exact*
   command. Fails closed: any error, timeout, or "Deny" rejects.
3. **Execution** — the daemon runs the approved `argv` directly (no shell) as
   root and returns stdout/stderr/exit-code.
4. **Audit** — every decision is appended to a root-owned JSONL log.

Approval authorizes **one command**, not a session. The agent never sees a
password and never gets a root shell.

```
agent ──unix socket──▶ sudixd (root)
                          │ SO_PEERCRED: caller uid in agent_uids?
                          │ policy: argv matches an allow rule?
                          │ cwd: canonicalize + exist + is_dir?
                          │ rate limit: within per-rule limit?
                          │ cache: recently approved same argv? (optional TTL)
                          │ approval: human approves THIS command?
                          │ execute argv as root
                          │ append audit line
                          └─▶ {exit_code, stdout, stderr}
```

## Layout

| Module      | Responsibility                                                     |
|-------------|--------------------------------------------------------------------|
| `protocol`  | Newline-delimited JSON wire types (`Request`, `Response`).         |
| `policy`    | Regex matching against shell-quoted argv rendering. The policy gate. |
| `approval`  | `Approver` trait + `ZenityApprover` + `TotpApprover`. Fail-closed. |
| `scoping`   | Per-rule TTL cache, rate limiting, injectable clock.               |
| `audit`     | Append-only JSONL log.                                             |
| `config`    | Load + validate `/etc/sudix/policy.toml`.                          |
| `server`    | Socket loop, peer-cred auth, decision pipeline, concurrency.       |

Binaries: `sudixd` (the daemon) and `sudix` (the thin client).

## Quick start

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for full install/config/release instructions.

1. **Build:**
   ```sh
   cargo build --release
   ```

2. **Generate a starter config:**
   ```sh
   sudo mkdir -p /etc/sudix
   sudo sudixd default-config > /etc/sudix/policy.toml
   sudo chown root:root /etc/sudix/policy.toml
   sudo chmod 644 /etc/sudix/policy.toml
   # Edit agent_uids / approver_uids to your uid(s).
   ```

3. **Run the daemon:**
   ```sh
   sudo SUDIX_RUNTIME_DIR=/run/sudix sudixd
   ```

4. **Submit a request:**
   ```sh
   sudix --reason "install ripgrep" -- pacman -S --noconfirm ripgrep
   ```

## Configuration

Policy lives in `/etc/sudix/policy.toml` (override: `$SUDIX_CONFIG`). The file
must be owned by root and not group- or world-writable. Generate a starter:

```sh
sudixd default-config
```

The daemon hot-reloads the policy on each incoming request when the file's
mtime changes — **no restart required** after editing `policy.toml`. If the
file fails to load (bad TOML, invalid regex), the request is refused and the
old in-memory policy is kept until the file is fixed.

### Rule format

Rules match a **regex** against a canonical rendering of the requested argv:
- `argv[0]` is reduced to its basename (`/usr/bin/pacman` → `pacman`), so
  path-spelling can't dodge a rule.
- Every token is POSIX shell-quoted; tokens are joined with single spaces.
  Example: `["rm", "-rf /"]` renders as `rm '-rf /'` (space-containing args
  are quoted, preventing token-boundary spoofing).

Patterns are **unanchored** by default. `id` matches `id -u` (renders `id -u`).
Anchor with `^` and `$` to match exactly: `^id$` matches only `["id"]`.
`.*` is the "match everything" pattern.

**`deny` is evaluated before `allow`.** A command matching any deny rule is
refused even if an allow rule would also match it.

Key fields:

```toml
# UIDs allowed to submit requests (agent service accounts).
agent_uids = [1000]
# UIDs whose presence the approval step is meant to prove.
approver_uids = [1000]

# Deny rules (optional; checked before allow).
deny = [
  { argv = "^(sh|bash)( |$)" },
]

# Allow rules.
allow = [
  { argv = "^pacman -S " },
  { argv = "^id$" },
  # cache_ttl_secs = 300  # optional: auto-approve same argv for N seconds
  # rate_per_min   = 10   # optional: max approvals/min (over limit → denied)
]

[approval]
# "agent" (desktop GUI via sudix-agent) or "totp" (headless).
method = "agent"
# totp_secret_path = "/etc/sudix/totp.key"  # required when method = "totp"
```

## Environment variables

| Variable          | Component | Default                   | Purpose                    |
|-------------------|-----------|---------------------------|----------------------------|
| `SUDIX_CONFIG`    | daemon    | `/etc/sudix/policy.toml`  | Config file path           |
| `SUDIX_RUNTIME_DIR` | both    | `/run/sudix`              | Socket + audit log dir     |
| `SUDIX_SOCKET`    | client    | `/run/sudix/sudixd.sock`  | Override socket path       |

## Status

Production-hardened. All items from the initial sketch are now implemented:

- Policy loaded from a root-owned TOML config; `sudixd default-config` prints a starter.
- Hot-reload: policy changes take effect on the next request; no restart needed.
- Regex rules matched against shell-quoted, basename-normalized argv rendering.
- Unified `deny`/`allow` rule arrays; deny takes precedence.
- cwd canonicalized and validated before exec.
- Per-rule TTL cache, rate limiting, approval caching (server-side; agent can't reach).
- TOTP headless approval path (`sudixd enroll`); agent dialog for desktop.
- Concurrent connections (thread-per-connection + serialized approval gate).
- systemd unit + socket activation (`dist/systemd/`).
- Agent vs. approver UID separation.
- `sudix --help` prints usage.
