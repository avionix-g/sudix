# sudix

A minimal privileged-action broker for coding agents.

## Problem

A coding agent running under your user account sometimes needs root. The usual
options all hand it more than you want:

- `NOPASSWD` sudoers → unattended, unbounded root.
- A stored password (a la askpass helpers) → after one approval the agent holds
  a reusable root credential, and the "security checks" guarding it (cwd,
  parent-process name, env vars) are all forgeable *by the agent*.

## Approach

`sudix` does not give the agent a credential. The agent **requests** a specific
command; a root daemon decides:

1. **Policy** (deny-by-default allowlist, plus a non-overridable hard denylist)
   — runs server-side, so the agent can't forge it. Denied requests never reach
   the human.
2. **Approval** — an out-of-band `zenity` dialog showing the *exact* command.
   Fails closed: any error, timeout, or "Deny" rejects.
3. **Execution** — the daemon runs the approved `argv` directly (no shell, no
   injection surface) as root and returns stdout/stderr/exit-code.
4. **Audit** — every decision is appended to a root-owned JSONL log.

Approval authorizes **one command**, not a session. The agent never sees a
password and never gets a root shell.

```
agent ──unix socket──▶ sudixd (root)
                          │ SO_PEERCRED: caller uid == allowed uid?
                          │ policy: argv matches an allow rule?  (deny by default)
                          │ zenity: human approves THIS command?  (fail closed)
                          │ execute argv as root
                          │ append audit line
                          └─▶ {exit_code, stdout, stderr}
```

## Layout

| Module      | Responsibility                                            |
|-------------|-----------------------------------------------------------|
| `protocol`  | Newline-delimited JSON wire types.                        |
| `policy`    | Allowlist matching (`*` = one arg, `**` = rest). The gate.|
| `approval`  | `Approver` trait + `ZenityApprover`. Fail-closed.         |
| `audit`     | Append-only JSONL log.                                    |
| `server`    | Socket loop, peer-cred auth, decision pipeline.           |

Binaries: `sudixd` (the daemon) and `sudix` (the thin client).

## Usage (sketch)

Run the daemon as root, telling it which uid may call it:

```sh
sudo SUDIX_ALLOWED_UID="$(id -u)" SUDIX_RUNTIME_DIR=/run/sudix sudixd
```

Then, as your user / the agent:

```sh
sudix --reason "install ripgrep" -- pacman -S --noconfirm ripgrep
```

Environment:

- `SUDIX_ALLOWED_UID` (daemon, required) — the one uid permitted to connect.
- `SUDIX_RUNTIME_DIR` (both, default `/run/sudix`) — socket + audit log dir.
- `SUDIX_SOCKET` (client, default `/run/sudix/sudixd.sock`) — socket path.

The starter allowlist and hard denylist live in `src/bin/sudixd.rs`.

## Status

Sketch / proof of concept. Known gaps before this is production-worthy:

- Policy is compiled in, not loaded from a root-owned config file.
- No per-rule TTL, rate limiting, or approval caching.
- No systemd unit / socket activation.
- zenity-only approval; no headless (TOTP / push) path.
- Single-threaded accept loop (fine for low request volume; a slow approval
  dialog blocks other requests).
- `cwd` is taken from the client and used verbatim for execution — it is
  attacker-influenced context, not validated.
