//! BUNYIP-253: HaveIBeenPwned k-anonymity breach check for the
//! server-side `/register` + `/reset-password` POST handlers.
//!
//! The client-side check shipped in BUNYIP-240 (k-anonymity SHA-1 lookup
//! from the SPA) is bypassable by any non-browser POST: a CLI / forged
//! fetch hits `/register` directly with the breached password and lands
//! a row in `users`. This module is the server-side backstop so the
//! breach check survives every entry point.
//!
//! Privacy posture matches the client check: the password's SHA-1 is
//! computed in-process, only the first 5 hex chars are sent to
//! `https://api.pwnedpasswords.com/range/{prefix}`, and the response is
//! a list of `SUFFIX:COUNT` lines. The plaintext password never leaves
//! the server. See <https://haveibeenpwned.com/API/v3#PwnedPasswords>.
//!
//! Failure mode: the HIBP endpoint being down does NOT block legitimate
//! signup. `is_breached` returns `Ok(false)` (treats unknown as safe)
//! after logging a warn, so a transient HIBP outage degrades to "no
//! server backstop this minute" rather than "no one can sign up".

use sha1::{Digest, Sha1};
use std::time::Duration;

/// BUNYIP-253: HIBP range endpoint. The trailing slash is part of the
/// shape ("`/range/{prefix}`"). HTTPS is mandatory: a downgrade would
/// leak the SHA-1 prefix to any on-path observer.
const HIBP_RANGE_BASE: &str = "https://api.pwnedpasswords.com/range/";

/// Per-call timeout. HIBP's range endpoint usually answers in <100ms;
/// a 3s deadline keeps a slow upstream from holding the signup actor
/// indefinitely.
const HIBP_TIMEOUT_SECS: u64 = 3;

/// Outcome of a single HIBP lookup.
#[derive(Debug)]
pub enum BreachCheckOutcome {
    /// The password's SHA-1 suffix appeared in the HIBP range response.
    /// The caller MUST reject the registration / reset.
    Breached,
    /// The suffix was not in the range. Caller proceeds.
    NotBreached,
    /// HIBP unreachable / non-200 / parse failure. Logged as a warning
    /// by `is_breached`; the caller proceeds (fail-open) so a transient
    /// outage doesn't lock new users out.
    Unknown,
}

/// Check whether `password` appears in HaveIBeenPwned via the
/// k-anonymity range API. The first 5 hex chars of the SHA-1 hash are
/// sent in the URL path; nothing else leaves the process.
pub async fn check_password_breach(password: &str) -> BreachCheckOutcome {
    let hash_hex = sha1_hex(password);
    let (prefix, suffix) = hash_hex.split_at(5);

    let url = format!("{HIBP_RANGE_BASE}{prefix}");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(HIBP_TIMEOUT_SECS))
        // Refuse redirects: a 302 from `api.pwnedpasswords.com` would
        // leak the prefix to a non-HIBP host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "HIBP client build failed; skipping backstop");
            return BreachCheckOutcome::Unknown;
        }
    };

    let body = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(error = %e, "HIBP body read failed; treating as Unknown");
                return BreachCheckOutcome::Unknown;
            }
        },
        Ok(resp) => {
            tracing::warn!(
                status = %resp.status(),
                "HIBP non-success status; treating as Unknown"
            );
            return BreachCheckOutcome::Unknown;
        }
        Err(e) => {
            tracing::warn!(error = %e, "HIBP request failed; treating as Unknown");
            return BreachCheckOutcome::Unknown;
        }
    };

    let upper_suffix = suffix.to_ascii_uppercase();
    for line in body.lines() {
        let entry = line.split(':').next().unwrap_or("").trim();
        if entry.eq_ignore_ascii_case(&upper_suffix) {
            return BreachCheckOutcome::Breached;
        }
    }
    BreachCheckOutcome::NotBreached
}

/// Convenience wrapper: returns `true` ONLY when HIBP confirmed a match.
/// `Unknown` (outage, parse failure) is mapped to `false` so the caller
/// fails open. The wrapper does the warning-log on outage so call sites
/// can treat the API as boolean without dropping that signal.
pub async fn is_breached(password: &str) -> bool {
    matches!(
        check_password_breach(password).await,
        BreachCheckOutcome::Breached
    )
}

fn sha1_hex(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let bytes = hasher.finalize();
    hex::encode(bytes).to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-1("password") = `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
    /// Pin the helper so a future bump cannot quietly change the hash.
    #[test]
    fn sha1_hex_matches_known_password() {
        assert_eq!(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    /// Prefix is always 5 hex chars (20 bits) so the range API yields a
    /// manageable response set; the suffix is the remaining 35 chars.
    #[test]
    fn sha1_hex_is_uppercase_and_40_chars() {
        let h = sha1_hex("hunter2");
        assert_eq!(h.len(), 40);
        assert_eq!(h, h.to_ascii_uppercase());
    }
}
