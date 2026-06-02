# Developing sudix

## Prerequisites

- Rust 1.95+ (edition 2024)
- `just`
- `zenity` (runtime only, for the desktop approval agent)

## Common recipes

```sh
just build           # debug build, all targets
just test            # run the test suite
just prep            # fmt + lint + machete + build + test (pre-commit gate)
just build-release   # release build
just install         # build, install binaries + systemd units, start services (root)
just uninstall       # stop services, remove binaries + units (root)
```

`just prep` must pass before committing.

## Binaries

| Binary        | Role                                                          |
|---------------|--------------------------------------------------------------|
| `sudixd`      | Root daemon: policy gate, approval, execution, audit.        |
| `sudix`       | Client the agent runs in place of `sudo`.                    |
| `sudix-agent` | Per-user approval agent; shows the zenity dialog in the GUI. |

## Layout

| Module      | Responsibility                                                     |
|-------------|--------------------------------------------------------------------|
| `protocol`  | Newline-delimited JSON wire types (`Request`, `Response`).         |
| `policy`    | Per-token matching (literal / anchored-regex / rest). The gate.    |
| `approval`  | `Approver` trait + `ZenityApprover` + `TotpApprover`. Fail-closed. |
| `scoping`   | Per-rule TTL cache, rate limiting, injectable clock.               |
| `audit`     | Append-only JSONL log.                                             |
| `config`    | Load + validate `/etc/sudix/policy.toml`.                          |
| `server`    | Socket loop, peer-cred auth, decision pipeline, concurrency.       |

## Tests

- **Unit** (`#[cfg(test)]` in each module): policy matching, config
  parse/validate, scoping (cache, TTL, rate limit), TOTP, cwd validation,
  protocol round-trips, client arg parsing, audit log.
- **Integration** (`tests/socket_roundtrip.rs`): drives a real broker over a
  real Unix socket; the test process is its own `SO_PEERCRED` peer.

All tests run unprivileged as the current user.

## Decision pipeline

For each request `sudixd` checks, in order:

1. `SO_PEERCRED` -- caller uid in `agent_uids`?
2. Policy -- `deny` rules (first), then `allow` rules.
3. cwd -- canonicalize, must exist and be a directory.
4. Rate limit -- within the rule's `rate_per_min`?
5. Cache -- identical argv approved within `cache_ttl_secs`?
6. Approval -- human approves *this* argv (zenity or TOTP).
7. Execute `argv` directly as root (no shell); append an audit line.

Any error, timeout, or denial fails closed. Approval authorizes one command,
never a session. The daemon hot-reloads `policy.toml` when its contents change
(SHA-256); a bad file is refused and the old in-memory policy is kept.

## Exit codes (client)

| Code  | Meaning                                                        |
|-------|---------------------------------------------------------------|
| `0`   | Command ran; exit code forwarded from the subprocess.         |
| `125` | Approver error (agent not running, spawn failure). Not a deny.|
| `126` | Explicitly denied (user clicked Deny, or wrong TOTP code).    |

## Releasing

`just install` is the canonical path. It installs binaries to `/usr/bin`,
writes a default `/etc/sudix/policy.toml` if absent, installs the systemd
units from `dist/systemd/`, and (re)starts `sudixd.socket` and the per-user
`sudix-agent.service`.

After install, review `/etc/sudix/policy.toml`:

- Set `agent_uids` / `approver_uids` to real uids.
- Restrict `allow` to low-blast-radius commands.
- For headless hosts, set `method = "totp"` and run `just enroll`.
- Confirm the file is root-owned and not world-writable.

**Socket mode:** `sudixd.socket` uses `SocketMode=0666`; authorization is
enforced by `SO_PEERCRED`, not filesystem permissions. Uids not in
`agent_uids` are refused before policy runs. Tighten to `0660` +
`SocketGroup=sudix` for filesystem-level defense in depth.

## Running without systemd

```sh
sudo SUDIX_RUNTIME_DIR=/run/sudix sudixd &
sudix-agent &   # in the graphical session as the normal user
```

The daemon creates `/run/sudix/`, binds `/run/sudix/sudixd.sock`, and writes
`/run/sudix/audit.log`. If `sudix-agent` is not running when a request arrives,
the broker waits up to 10 s for it to register, then returns an error -- never a
silent denial.

## Environment variables

| Variable            | Component | Default                  | Purpose              |
|---------------------|-----------|--------------------------|----------------------|
| `SUDIX_CONFIG`      | daemon    | `/etc/sudix/policy.toml` | Config file path     |
| `SUDIX_RUNTIME_DIR` | both      | `/run/sudix`             | Socket + audit dir   |
| `SUDIX_SOCKET`      | client    | `/run/sudix/sudixd.sock` | Override socket path |
