//! Admin panel: IP auto-bans (BUNYIP-320).

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{
    AdminApplication, AdminAuditLog, AdminErrorLog, AdminFeedbackDetail, AdminIpBan,
    AdminRateLimit, AdminRateLimitConfig, AdminUser, AppRestoreStatus, ApplicationGroup,
    FeedbackAttachmentMeta, FeedbackStatus, RestoreReport, User, UserEntitlement,
};
use crate::auth::AuthCtx;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{relative_time, urlenc};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{badge, button_class, error_box, icon, success_box, toggle_switch};
use crate::web::{redirect, redirect_cookies, AppState};

use super::refuse_non_super_admin;
use super::{pager, title_case};

/// Render one active IP auto-ban row: the banned IP, reason, strike count, when
/// it was banned and when it expires, plus an Unban button that POSTs to the
/// lift handler.
fn ip_ban_row(b: &AdminIpBan) -> Markup {
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10" { (icon("shield-off", "h-5 w-5 text-destructive")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium font-mono break-all" { (b.ip) }
                        (badge("destructive", "Banned"))
                        (badge("warning", &format!("{} strikes", b.strikes)))
                    }
                    p class="text-sm text-muted-foreground break-words" { (b.reason) }
                    p class="text-xs text-muted-foreground" {
                        "Banned " (relative_time(&b.banned_at)) " • expires " (relative_time(&b.expires_at))
                    }
                }
            }
            form method="post" action="/admin/ip-bans/unban" data-confirm=(format!("Lift the ban on {}? It takes effect on the next request.", b.ip)) {
                input type="hidden" name="ip" value=(b.ip);
                button type="submit" class=(button_class("outline", "sm", "")) { "Unban" }
            }
        }
    }
}

/// Default manual-ban duration offered by the form: 24 hours, matching the
/// API's default. The API bounds the value; the input mirrors those bounds.
const DEFAULT_MANUAL_BAN_SECS: i64 = 86_400;
const MIN_MANUAL_BAN_SECS: i64 = 60;
const MAX_MANUAL_BAN_SECS: i64 = 31_536_000;

/// The "add a ban" card (BUNYIP-413): address, reason and duration. Rendered
/// only for the super admin, who is the only account the API will accept it
/// from.
/// `prefill_ip` seeds the address field so a "Ban this address" link from
/// elsewhere (BUNYIP-436: the feedback detail IP) lands here ready to submit.
fn ip_ban_add_card(prefill_ip: Option<&str>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { (icon("shield-off", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Add Ban" } }
                p class="text-sm text-muted-foreground" { "Block an address by hand. The ban takes effect on its next request and expires on its own." }
            }
            div class="p-6 pt-0" {
                form method="post" action="/admin/ip-bans/add" class="grid gap-4 sm:grid-cols-4 sm:items-end" {
                    div class="space-y-2 sm:col-span-1" { label class="text-sm font-medium" { "IP address" } input name="ip" required placeholder="203.0.113.7" value=(prefill_ip.unwrap_or_default()) class=(dashboard_input()); }
                    div class="space-y-2 sm:col-span-2" { label class="text-sm font-medium" { "Reason" } input name="reason" required maxlength="255" placeholder="Credential stuffing" class=(dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Duration (seconds)" } input name="duration_secs" type="number" min=(MIN_MANUAL_BAN_SECS) max=(MAX_MANUAL_BAN_SECS) value=(DEFAULT_MANUAL_BAN_SECS) class=(dashboard_input()); }
                    div class="sm:col-span-4" { button type="submit" class=(button_class("default", "default", "")) { (icon("shield-off", "mr-2 h-4 w-4")) "Ban address" } }
                }
            }
        }
    }
}

/// Query for the IP bans page. `ip` prefills the add-ban form so a
/// "Ban this address" link (BUNYIP-436: from the feedback detail IP) arrives
/// ready to submit.
#[derive(Deserialize)]
pub struct IpBansQuery {
    pub ip: Option<String>,
}

/// Admin IP auto-ban view (BUNYIP-320): the currently-active IP bans surfaced by
/// the subtask 7 endpoint, each liftable in place. AdminUser-guarded like the
/// other admin pages; the add form (BUNYIP-413) is super-admin-only.
pub async fn ip_bans(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IpBansQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::ip_bans(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let bans = data.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "IP Bans" } p class="mt-2 text-muted-foreground" { "IP addresses banned for abusive request patterns, automatically or by hand. Adding or lifting a ban takes effect on the address's next request." } }
            @if user.is_super_admin { (ip_ban_add_card(q.ip.as_deref())) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("shield-off", "h-5 w-5 text-destructive")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Active Bans" } }
                    @if reachable { p class="text-sm text-muted-foreground" { (bans.len()) " active." } }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load IP bans."))
                    } @else if bans.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No active IP bans." }
                    } @else {
                        // BUNYIP-415: flow ban rows into two columns (one below
                        // lg) so the list uses the width instead of a single
                        // narrow stack.
                        div class="grid gap-x-8 lg:grid-cols-2" { @for b in &bans { (ip_ban_row(b)) } }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/ip-bans", "IP Bans · Bunyip", content)
}

/// Form body for the add-ban action (BUNYIP-413). `duration_secs` is a string
/// so a typo comes back as a toast rather than a 422 from extraction.
#[derive(Deserialize)]
pub struct CreateBanForm {
    pub ip: String,
    pub reason: String,
    #[serde(default)]
    pub duration_secs: String,
}

/// Ban an IP by hand (BUNYIP-413), then redirect back to the list with a
/// success/error toast. Super-admin-only, enforced again by the API, which
/// validates the address, reason and duration and audits the ban.
pub async fn ip_ban_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateBanForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/ip-bans") {
        return refusal;
    }
    let duration = match f.duration_secs.trim() {
        "" => DEFAULT_MANUAL_BAN_SECS,
        raw => match raw.parse::<i64>() {
            Ok(n) => n,
            Err(_) => {
                return redirect_cookies(
                    "/admin/ip-bans?toast_err=Duration%20must%20be%20a%20whole%20number",
                    &c.set_cookies,
                )
            }
        },
    };
    let target = match admin_api::create_ip_ban(
        &st.api,
        c.forward.as_deref(),
        f.ip.trim(),
        f.reason.trim(),
        duration,
    )
    .await
    {
        Ok(()) => format!("/admin/ip-bans?toast_ok=Banned%20{}", urlenc(f.ip.trim())),
        Err(e) => format!("/admin/ip-bans?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Form body for the unban action: the IP to lift, carried in a hidden field so
/// an IPv6 address never has to sit in the URL path.
#[derive(Deserialize)]
pub struct UnbanForm {
    pub ip: String,
}

/// Lift an IP auto-ban (BUNYIP-320), then redirect back to the list with a
/// success/error toast. AdminUser-guarded.
pub async fn ip_unban(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<UnbanForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unban_ip(&st.api, c.forward.as_deref(), &f.ip).await {
        Ok(()) => format!(
            "/admin/ip-bans?toast_ok=Ban%20lifted%20for%20{}",
            urlenc(&f.ip)
        ),
        Err(_) => "/admin/ip-bans?toast_err=Could%20not%20lift%20ban".to_string(),
    };
    redirect_cookies(&target, &c.set_cookies)
}
