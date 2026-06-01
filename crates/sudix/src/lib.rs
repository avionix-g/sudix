//! `sudix` — a minimal privileged-action broker for coding agents.
//!
//! The problem: a coding agent running as you sometimes needs root, but giving
//! it a stored password or a `NOPASSWD` sudoers rule hands it unattended,
//! unbounded root. `sudix` instead lets the agent *request* a specific command;
//! the broker (running as root) checks it against server-side policy, asks a
//! human to approve that exact command, runs it itself, and returns the output.
//! The agent never holds a credential and approval authorizes one command, not
//! a session.
//!
//! Layering:
//! * [`protocol`] — the newline-JSON wire types.
//! * [`policy`] — deny-by-default allowlist matching (the forgery-proof gate).
//! * [`approval`] — out-of-band, fail-closed human approval.
//! * [`audit`] — append-only log of every decision.
//! * [`server`] — ties them together over a unix socket with peer-cred auth.

pub mod approval;
pub mod audit;
pub mod config;
pub mod policy;
pub mod protocol;
pub mod server;

pub use approval::{Approver, ZenityApprover};
pub use config::ConfigError;
pub use policy::{Policy, Rule, Verdict};
pub use protocol::{Request, Response};
