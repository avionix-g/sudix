# Next steps & caveats

Status: sketch / proof of concept. The core pipeline (peer-cred auth → policy →
approval → execute → audit) works end to end and is tested, but several things
must change before this guards real root access.

## Next steps

1. **Externalize policy.** The allowlist and hard denylist are compiled into
   `src/bin/sudixd.rs`. Load them from a root-owned, non-world-writable config
   file instead, so policy can change without a rebuild and is reviewable as
   data. Validate `**` placement at load time (the `Rule` constructor already
   enforces it).
2. **Validate `cwd`.** The client supplies `cwd` and the daemon `current_dir`s
   into it verbatim before executing as root — attacker-influenced input. At
   minimum canonicalize it and confirm it exists and is a directory; consider an
   allowed-prefix list, or dropping client-supplied cwd entirely.
3. **Approval scoping controls.** Add per-rule TTL, rate limiting, and optional
   short-lived approval caching so the human isn't prompted for every invocation
   of a low-risk command — enforced server-side where the agent can't reach.
4. **Headless approval.** zenity requires a desktop. Add an out-of-band path for
   headless/SSH hosts (TOTP challenge or phone push), keeping the fail-closed
   contract.
5. **systemd integration.** Ship a unit + socket activation so the daemon runs
   as root under supervision with the runtime dir and permissions set up.
6. **Concurrency.** The accept loop is single-threaded, so a slow approval
   dialog blocks other requests. Fine at low volume; revisit (per-connection
   threads with a serialized approval queue) if that becomes a problem.

## UID caveat

The daemon authorizes exactly one uid (`SUDIX_ALLOWED_UID`) via `SO_PEERCRED`,
which the kernel vouches for and the peer cannot spoof. This assumes **the agent
and the human share a uid** — the model is "you, sitting at this machine, may
request root, and you approve each command."

If the agent ever runs under its **own** uid (e.g. a sandboxed service account),
you would authorize *that* uid, and peer-cred auth then proves only "the agent
connected," not "the human is present." The approval dialog still gates every
command, so this degrades **safely** (the agent can't self-approve) rather than
dangerously — but the "is the human really here?" guarantee is weaker, and a
compromised agent could spam approval prompts. If that deployment is intended,
bind approval to a stronger human signal (TOTP/push, per step 4) rather than
relying on the dialog alone.

## Documentation

Document testing, building, releasing.
