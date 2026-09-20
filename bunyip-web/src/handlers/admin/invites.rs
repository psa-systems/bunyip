//! Admin panel: admin invites (BUNYIP-760).
//!
//! The API has supported creating, listing and revoking admin invites since
//! before bunyip-web existed (`/v1/admin/invites`); only the consumer-facing
//! half (`/auth/invite/accept`) had a caller. This gives the admin panel the
//! producer side: send an invite, see who is pending/accepted/revoked, and
//! revoke a pending one.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::AdminInvite;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{rel_time, urlenc};
use crate::views::ui::{badge, button_class, empty_state, error_box, icon, pager};
use crate::web::{redirect_cookies, AppState};

use super::PageQuery;

/// The invite's current state, derived the same way the API model does
/// (`AdminInvite::is_revoked` / `is_accepted` / `is_expired`), since the wire
/// type carries the raw timestamps rather than a precomputed label.
fn invite_status(inv: &AdminInvite) -> (&'static str, &'static str) {
    if inv.revoked_at.is_some() {
        ("secondary", "Revoked")
    } else if inv.accepted_at.is_some() {
        ("success", "Accepted")
    } else if inv.expires_at.as_str() < chrono_now_rfc3339().as_str() {
        ("warning", "Expired")
    } else {
        ("outline", "Pending")
    }
}

/// RFC3339 "now", used only to compare against an invite's `expires_at`
/// string: both are RFC3339, so a lexical compare is a valid ordering.
fn chrono_now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Render one invite row: email, status badge, who invited and when, plus a
/// Revoke button for a still-pending invite.
fn invite_row(inv: &AdminInvite) -> Markup {
    let (variant, label) = invite_status(inv);
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted" { (icon("mail", "h-5 w-5 text-muted-foreground")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium break-all" { (inv.email) }
                        (badge(variant, label))
                    }
                    p class="text-xs text-muted-foreground" {
                        "Invited " (rel_time(&inv.created_at)) " · expires " (rel_time(&inv.expires_at))
                    }
                }
            }
            @if label == "Pending" {
                form method="post" action=(format!("/admin/invites/{}/revoke", urlenc(&inv.id))) data-confirm=(format!("Revoke the invite for {}?", inv.email)) {
                    button type="submit" class=(button_class("outline", "sm", "")) { "Revoke" }
                }
            }
        }
    }
}

/// The "send an invite" card: an email address, submitted to the create
/// endpoint. Any admin may send one; the API is the enforcement point.
fn invite_create_card() -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { (icon("user-plus", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Invite an Admin" } }
                p class="text-sm text-muted-foreground" { "Sends an email with a link to accept and set a password. Any pending invite for the same address is revoked first." }
            }
            div class="p-6 pt-0" {
                form method="post" action="/admin/invites" class="grid gap-4 sm:grid-cols-4 sm:items-end" {
                    div class="space-y-2 sm:col-span-3" { label for="email" class="text-sm font-medium" { "Email" } input id="email" name="email" type="email" required placeholder="new-admin@example.com" class=(dashboard_input()); }
                    div { button type="submit" class=(button_class("default", "default", "w-full")) { (icon("user-plus", "mr-2 h-4 w-4")) "Send invite" } }
                }
            }
        }
    }
}

/// Admin invites view (BUNYIP-760): send an invite, and see pending / accepted
/// / revoked / expired invites with a Revoke action on pending ones.
/// AdminUser-guarded like the other admin pages; no super-admin restriction,
/// matching the API's `AdminUser` guard on all three endpoints.
pub async fn invites(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::admin_invites(&st.api, c.forward.as_deref(), page, 20).await;
    let reachable = data.is_ok();
    let (items, total, total_pages) = match data {
        Ok(p) => (p.items, p.total, p.total_pages),
        Err(_) => (Vec::new(), 0, 1),
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Admin Invites" } p class="mt-2 text-muted-foreground" { "Invite new admins by email, and manage pending invites." } }
            (invite_create_card())
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("mail", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Invites" } }
                    @if reachable { p class="text-sm text-muted-foreground" { (total) " total." } }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load invites."))
                    } @else if items.is_empty() {
                        (empty_state("mail", "No invites yet.", None))
                    } @else {
                        div { @for inv in &items { (invite_row(inv)) } }
                        (pager("/admin/invites", "page", page, total_pages))
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/invites", "Admin Invites", content)
}

/// Form body for creating an invite: the email alone.
#[derive(Deserialize)]
pub struct CreateInviteForm {
    pub email: String,
}

/// Send an admin invite (BUNYIP-760), then redirect back to the list with a
/// success/error toast.
pub async fn invite_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateInviteForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let email = f.email.trim();
    let target = match admin_api::create_admin_invite(&st.api, c.forward.as_deref(), email).await {
        Ok(()) => format!("/admin/invites?toast_ok=Invited%20{}", urlenc(email)),
        Err(e) => format!("/admin/invites?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Revoke a pending admin invite (BUNYIP-760), then redirect back to the list
/// with a success/error toast.
pub async fn invite_revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(invite_id): axum::extract::Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target =
        match admin_api::revoke_admin_invite(&st.api, c.forward.as_deref(), &invite_id).await {
            Ok(()) => "/admin/invites?toast_ok=Invite%20revoked".to_string(),
            Err(e) => format!("/admin/invites?toast_err={}", urlenc(&e.user_message())),
        };
    redirect_cookies(&target, &c.set_cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(revoked: bool, accepted: bool) -> AdminInvite {
        AdminInvite {
            id: "11111111-1111-1111-1111-111111111111".into(),
            email: "new-admin@example.com".into(),
            invited_by: "22222222-2222-2222-2222-222222222222".into(),
            role: "admin".into(),
            expires_at: (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
            accepted_at: accepted.then(|| chrono::Utc::now().to_rfc3339()),
            revoked_at: revoked.then(|| chrono::Utc::now().to_rfc3339()),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn pending_invite_row_offers_revoke() {
        let html = invite_row(&sample(false, false)).into_string();
        assert!(html.contains("new-admin@example.com"));
        assert!(html.contains("Pending"));
        assert!(
            html.contains(r#"action="/admin/invites/11111111-1111-1111-1111-111111111111/revoke""#)
        );
    }

    #[test]
    fn revoked_invite_row_has_no_revoke_button() {
        let html = invite_row(&sample(true, false)).into_string();
        assert!(html.contains("Revoked"));
        assert!(!html.contains("/revoke\""));
    }

    #[test]
    fn accepted_invite_row_has_no_revoke_button() {
        let html = invite_row(&sample(false, true)).into_string();
        assert!(html.contains("Accepted"));
        assert!(!html.contains("/revoke\""));
    }
}
