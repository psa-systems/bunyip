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

pub use dunite_hibp::{check_password_breach, BreachCheckOutcome};

#[cfg(not(test))]
pub use dunite_hibp::is_breached;

/// BUNYIP-947: a test-only override so a regression test can stub "this
/// password is breached" without a real HIBP call. Thread-local because
/// `#[tokio::test]` defaults to a current-thread runtime (one OS thread per
/// test), so there is no cross-test leakage to guard against.
#[cfg(test)]
pub use test_support::is_breached;

#[cfg(test)]
pub mod test_support {
    use std::cell::Cell;

    thread_local! {
        static OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    /// `Some(v)` makes `is_breached` return `v` without calling HIBP;
    /// `None` restores the real check.
    pub fn set_breach_override(value: Option<bool>) {
        OVERRIDE.with(|o| o.set(value));
    }

    pub async fn is_breached(password: &str) -> bool {
        if let Some(v) = OVERRIDE.with(|o| o.get()) {
            return v;
        }
        dunite_hibp::is_breached(password).await
    }
}
