//! Admin handlers. Server-rendered tables with query-param pagination and
//! form-based mutations (htmx is loaded for progressive enhancement, but the
//! baseline works without JS). Mirrors the Dioxus admin pages; the heavyweight
//! Stripe product/price/webhook managers remain condensed (see ROADMAP.md).
//!
//! DEV-517: the handlers are split one module per admin section, mirroring
//! a8n-tools' layout. The route wiring lives in `crate::routes::admin`.

mod application_groups;
mod applications;
mod audit;
mod auto_ban_settings;
mod backup;
mod dashboard;
mod email_config;
mod entitlements;
mod error_log;
mod feedback;
mod ip_bans;
mod memberships;
mod rate_limits;
mod seed;
mod stripe;
mod tier_settings;
mod users;

#[cfg(test)]
mod tests;

pub use application_groups::*;
pub use applications::*;
pub use audit::*;
pub use auto_ban_settings::*;
pub use backup::*;
pub use dashboard::*;
pub use email_config::*;
pub use entitlements::*;
pub use error_log::*;
pub use feedback::*;
pub use ip_bans::*;
pub use memberships::*;
pub use rate_limits::*;
pub use seed::*;
pub use stripe::*;
pub use tier_settings::*;
pub use users::*;

use axum::response::Response;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::types::User;
use crate::auth::AuthCtx;
use crate::views::ui::button_class;
use crate::web::redirect_cookies;

/// Page number plus the tier filter, shared by every paginated admin list
/// (BUNYIP-291 AC4).
#[derive(Deserialize)]
pub struct PageQuery {
    pub page: Option<u32>,
    /// BUNYIP-291 AC4: active tier filter for the members-by-tier view.
    #[serde(default)]
    pub tier: Option<String>,
}

/// BUNYIP-413: refuse a super-admin-only form to everybody else, as a redirect
/// back to `back` carrying a refusal toast. The API enforces the same gate, so
/// this is a friendlier message rather than the security boundary.
fn refuse_non_super_admin(user: &User, c: &AuthCtx, back: &str) -> Option<Response> {
    if user.is_super_admin {
        return None;
    }
    Some(redirect_cookies(
        &format!("{back}?toast_err=Only%20the%20super%20admin%20can%20change%20this"),
        &c.set_cookies,
    ))
}

/// Apply the BUNYIP-90 hardening header triple to any binary-proxy
/// response (attachment download, CSV export, backup bundle). Lives here
/// rather than beside one caller so future binary-serving routes in any
/// admin section get the same treatment by reference.
///
/// `X-Content-Type-Options: nosniff` forces the browser to respect the
/// upstream Content-Type and skip its own MIME sniffing - a text/plain
/// attachment that happens to contain `<script>` markup never becomes
/// HTML, even on legacy browsers.
///
/// `Content-Security-Policy: sandbox` sandboxes any inline-rendered
/// content (the strictest sandbox: no scripts, no forms, no
/// same-origin). Belt-and-suspenders defence in depth alongside
/// nosniff; if a future binary type accidentally lands HTML-ish into
/// this proxy, the sandbox neuters it.
///
/// `Referrer-Policy: no-referrer` prevents the attachment URL (which
/// contains feedback id + attachment id) from leaking via the Referer
/// header when the admin then navigates elsewhere.
fn with_attachment_hardening(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    builder
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "sandbox")
        .header("Referrer-Policy", "no-referrer")
}

fn title_case(action: &str) -> String {
    action
        .split('_')
        .map(|w| {
            let mut ch = w.chars();
            match ch.next() {
                Some(f) => f.to_uppercase().chain(ch).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn pager(base: &str, page: u32, total_pages: i64) -> Markup {
    let sep = if base.contains('?') { "&" } else { "?" };
    html! {
        @if total_pages > 1 {
            div class="flex justify-center gap-2 mt-6" {
                @if page > 1 { a href=(format!("{base}{sep}page={}", page - 1)) class=(button_class("outline", "sm", "")) { "Previous" } }
                span class="flex items-center px-3 text-sm" { "Page " (page) " of " (total_pages) }
                @if (page as i64) < total_pages { a href=(format!("{base}{sep}page={}", page + 1)) class=(button_class("outline", "sm", "")) { "Next" } }
            }
        }
    }
}
