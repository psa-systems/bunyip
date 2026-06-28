//! Small shared helpers ported from `src/lib/utils.ts`.

use chrono::{DateTime, Utc};

use crate::api::types::{Application, MembershipStatus, User, UserRole};

/// External URL for an app: `https://{subdomain|slug}.{domain}`, or `#` when no
/// apex domain is configured. Mirrors the `getAppUrl` helpers in LandingPage /
/// Footer.
pub fn app_link(app: &Application, domain: &str) -> String {
    let sub = app
        .subdomain
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&app.slug);
    if domain.is_empty() {
        "#".to_string()
    } else {
        format!("https://{sub}.{domain}")
    }
}

/// Tailwind gradient class pairs cycled across application cards.
pub const APP_GRADIENTS: [&str; 4] = [
    "from-indigo-500 to-primary",
    "from-teal-400 to-indigo-600",
    "from-primary to-teal-500",
    "from-violet-500 to-indigo-500",
];

pub fn app_gradient(index: usize) -> &'static str {
    APP_GRADIENTS[index % APP_GRADIENTS.len()]
}

fn is_future(iso: &str) -> bool {
    DateTime::parse_from_rfc3339(iso)
        .map(|d| d.with_timezone(&Utc) > Utc::now())
        .unwrap_or(false)
}

/// Mirrors `hasActiveMembership` / backend `has_member_access`.
pub fn has_active_membership(user: Option<&User>) -> bool {
    let Some(user) = user else { return false };
    user.role == UserRole::Admin
        || user.lifetime_member
        || user.trial_ends_at.as_deref().is_some_and(is_future)
        || user.membership_status == MembershipStatus::Active
        || user.membership_status == MembershipStatus::GracePeriod
}

/// Coarse "x ago" string for an ISO timestamp. Ported from `formatRelativeTime`.
pub fn relative_time(iso: &str) -> String {
    let Ok(then) = DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let secs = (Utc::now() - then.with_timezone(&Utc)).num_seconds().max(0);
    let days = secs / 86_400;
    if days == 0 {
        let hours = secs / 3600;
        if hours == 0 {
            let mins = secs / 60;
            if mins <= 1 {
                return "just now".to_string();
            }
            return format!("{mins} minutes ago");
        }
        return format!("{hours} hour{} ago", if hours == 1 { "" } else { "s" });
    }
    if days == 1 {
        return "yesterday".to_string();
    }
    if days < 7 {
        return format!("{days} days ago");
    }
    if days < 30 {
        let w = days / 7;
        return format!("{w} week{} ago", if w == 1 { "" } else { "s" });
    }
    if days < 365 {
        let m = days / 30;
        return format!("{m} month{} ago", if m == 1 { "" } else { "s" });
    }
    let y = days / 365;
    format!("{y} year{} ago", if y == 1 { "" } else { "s" })
}

/// Percent-encode a string for a URL query value (single source for the BFF).
///
/// Unreserved RFC 3986 chars pass through, space becomes `+`, everything else
/// is percent-encoded. Used by settings redirects, admin search, and admin API
/// calls so the three previously-drifted local copies stay one implementation.
pub fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Days left until an ISO timestamp, or None if it's in the past / unparseable.
pub fn days_until(iso: &str) -> Option<i64> {
    let then = DateTime::parse_from_rfc3339(iso).ok()?.with_timezone(&Utc);
    let diff = then - Utc::now();
    if diff.num_seconds() <= 0 {
        None
    } else {
        // ceil to whole days, matching the React Math.ceil.
        Some((diff.num_seconds() as f64 / 86_400.0).ceil() as i64)
    }
}
