//! HaveIBeenPwned k-anonymity password-breach check (BUNYIP-253).
//!
//! DEV-527: the implementation moved to the shared `dunite-hibp` crate, which
//! a8n-tools can adopt too. This module is kept as the seam so every
//! `crate::services::password_breach::*` path in bunyip is unchanged.
//!
//! Behaviour is identical: the password's SHA-1 is computed in-process, only
//! the first 5 hex chars are sent to `api.pwnedpasswords.com/range/{prefix}`,
//! and an HIBP outage fails open (`is_breached` returns `false` after a warn),
//! so a transient outage degrades to "no server backstop this minute" rather
//! than blocking signup.

pub use dunite_hibp::{check_password_breach, is_breached, BreachCheckOutcome};
