//! Small shared helpers ported from `src/lib/utils.ts`.

use chrono::{DateTime, Utc};
use maud::{html, Markup};

use crate::api::types::{Application, MembershipStatus, User, UserRole};

/// Format a Stripe price amount for display. A zero-amount lifetime price is
/// `Some(0)` -> "$0.00" (not "--"); a null amount -> "--".
///
/// BUNYIP-487: shared, because the public pricing page now renders the same
/// resolved amount the admin Stripe / Pricing tiers pages show. One formatter
/// means the marketing price and the admin price cannot be formatted apart.
pub fn format_stripe_amount(unit_amount: Option<i64>, currency: &str) -> String {
    match unit_amount {
        None => "--".to_string(),
        Some(cents) => {
            let whole = cents / 100;
            let frac = (cents % 100).abs();
            match currency.to_ascii_lowercase().as_str() {
                "usd" => format!("${whole}.{frac:02}"),
                "eur" => format!("€{whole}.{frac:02}"),
                "gbp" => format!("£{whole}.{frac:02}"),
                _ => format!("{whole}.{frac:02} {}", currency.to_uppercase()),
            }
        }
    }
}

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

/// Tailwind gradient class pairs an application card's accent is drawn from.
pub const APP_GRADIENTS: [&str; 4] = [
    "from-indigo-500 to-primary",
    "from-teal-400 to-indigo-600",
    "from-primary to-teal-500",
    "from-violet-500 to-indigo-500",
];

/// Accent for an application that belongs to no group: flat primary, so "no
/// group" reads as its own state instead of borrowing a group's colour.
pub const UNGROUPED_APP_GRADIENT: &str = "from-primary to-primary";

/// Accent for one application card, keyed to its group (BUNYIP-495). Colour
/// means "these belong together", so it only moves when an admin regroups the
/// application. It is deliberately NOT a function of the card's position: a
/// position-keyed accent repainted every tile whenever one was added, removed
/// or reordered, and taught nothing.
pub fn app_gradient(group_id: Option<&str>) -> &'static str {
    match group_id.filter(|g| !g.is_empty()) {
        None => UNGROUPED_APP_GRADIENT,
        Some(id) => APP_GRADIENTS[(fnv1a(id) % APP_GRADIENTS.len() as u64) as usize],
    }
}

/// FNV-1a. A fixed hash, not `DefaultHasher`, whose `RandomState` seed changes
/// per process and would repaint every tile on restart.
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
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

/// Format an ISO-8601 timestamp as a compact absolute time for the `title`
/// tooltip on a relative timestamp. Falls back to the raw string when it does
/// not parse.
fn abs_time(iso: &str) -> String {
    DateTime::parse_from_rfc3339(iso)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

/// Render an ISO-8601 timestamp as a `<time>` element (BUNYIP-466 F23): a
/// machine-readable `datetime`, an absolute-time `title` tooltip, and the coarse
/// `relative_time` string as the visible text. Single source for relative
/// timestamps across the dashboard/admin views.
pub fn rel_time(iso: &str) -> Markup {
    html! {
        time datetime=(iso) title=(abs_time(iso)) { (relative_time(iso)) }
    }
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

#[cfg(test)]
mod tests {
    use super::{app_gradient, app_link, fnv1a, APP_GRADIENTS, UNGROUPED_APP_GRADIENT};
    use crate::api::types::Application;

    fn app(slug: &str, subdomain: Option<&str>) -> Application {
        Application {
            id: "app-1".into(),
            slug: slug.into(),
            display_name: "Let's Chat".into(),
            description: None,
            icon_url: None,
            version: None,
            source_code_url: None,
            release_notes_url: None,
            subdomain: subdomain.map(str::to_string),
            is_accessible: false,
            maintenance_mode: false,
            maintenance_message: None,
            group_id: None,
        }
    }

    /// BUNYIP-533: the "Let's Chat" product is served at `chat.{app_domain}`, so
    /// its application row carries `subdomain = "chat"`; the link then resolves
    /// correctly on both environments (staging `a8n.systems`, prod `spa.systems`)
    /// because only the domain half varies. Without the subdomain the link fell
    /// back to the slug and pointed at the wrong host (`lets-chat.{app_domain}`),
    /// which is the bug the seed migration corrects.
    #[test]
    fn app_link_prefers_subdomain_over_slug() {
        let with = app("lets-chat", Some("chat"));
        assert_eq!(app_link(&with, "a8n.systems"), "https://chat.a8n.systems");
        assert_eq!(app_link(&with, "spa.systems"), "https://chat.spa.systems");

        // The pre-fix state: no subdomain -> slug fallback -> wrong host.
        let without = app("lets-chat", None);
        assert_eq!(
            app_link(&without, "a8n.systems"),
            "https://lets-chat.a8n.systems"
        );

        // No apex domain configured -> a neutral href, never a broken absolute.
        assert_eq!(app_link(&with, ""), "#");
    }

    /// BUNYIP-495: the accent follows the group, so every member of a group is
    /// painted alike and an application keeps its colour when the catalog is
    /// reordered. The old `app_gradient(index)` moved every tile's colour on any
    /// insert, delete or reorder.
    #[test]
    fn app_gradient_follows_the_group_not_the_position() {
        let a = "5f2b1c8e-0000-4000-8000-000000000001";
        let b = "9d7e4a11-0000-4000-8000-000000000002";

        // Same group -> same accent, however far apart the two cards render.
        assert_eq!(app_gradient(Some(a)), app_gradient(Some(a)));
        // Different groups -> the accent is drawn from the palette.
        assert!(APP_GRADIENTS.contains(&app_gradient(Some(b))));
        // Ungrouped is its own state, never a palette entry borrowed from a group.
        assert_eq!(app_gradient(None), UNGROUPED_APP_GRADIENT);
        assert_eq!(app_gradient(Some("")), UNGROUPED_APP_GRADIENT);
        assert!(!APP_GRADIENTS.contains(&UNGROUPED_APP_GRADIENT));
    }

    /// Every accent call site keys off the group, and nothing else. A source
    /// scan, because the signature alone would also accept the card's position
    /// converted to a string, which is the shape BUNYIP-495 removed.
    #[test]
    fn every_app_gradient_call_site_keys_off_the_group() {
        let sources = [
            (
                "handlers/dashboard.rs",
                include_str!("handlers/dashboard.rs"),
            ),
            ("skin/public.rs", include_str!("skin/public.rs")),
        ];
        for (name, src) in sources {
            for (n, line) in src.lines().enumerate() {
                let Some((_, arg)) = line.split_once("app_gradient(") else {
                    continue;
                };
                assert!(
                    arg.starts_with("app.group_id.as_deref()"),
                    "{name}:{} paints a tile from something other than its group",
                    n + 1
                );
            }
        }
    }

    /// The accent must survive a restart, so the hash is fixed rather than
    /// `DefaultHasher`, whose seed is randomised per process.
    #[test]
    fn app_gradient_is_stable_across_processes() {
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a("foobar"), 0x8594_4171_f739_67e8);
    }
}
