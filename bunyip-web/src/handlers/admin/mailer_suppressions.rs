//! Admin panel: mailer suppression list (BUNYIP-834).
//!
//! `list_mailer_suppressions` and `delete_mailer_suppression` have existed on
//! `bunyip-api` since BUNYIP-762 (read) with a delete added in the same
//! change, but nothing in bunyip-web called either: a real member whose
//! address gets suppressed after a bounce or spam complaint had no in-product
//! way to be found or unsuppressed. This gives the admin panel that surface,
//! mirroring the admin-invites page (BUNYIP-760).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::api::admin as admin_api;
use crate::api::types::MailerSuppression;
use crate::handlers::{admin_guard, admin_response, verification_gate};
use crate::util::{rel_time, urlenc};
use crate::views::ui::{empty_state, error_box, icon, pager};
use crate::web::redirect_cookies;
use crate::web::AppState;

use super::PageQuery;

/// Render one suppressed-address row: address, reason/detail, when it was
/// suppressed, and a Remove action.
fn suppression_row(s: &MailerSuppression) -> Markup {
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted" { (icon("shield-off", "h-5 w-5 text-muted-foreground")) }
                div class="min-w-0" {
                    p class="font-medium break-all" { (s.address) }
                    p class="text-xs text-muted-foreground" {
                        (s.reason)
                        @if let Some(detail) = &s.detail {
                            @if !detail.is_empty() {
                                ": " (detail)
                            }
                        }
                    }
                    p class="text-xs text-muted-foreground" { "Suppressed " (rel_time(&s.created_at)) }
                }
            }
            form method="post" action=(format!("/admin/mailer-suppressions/{}/delete", urlenc(&s.address))) data-confirm=(format!("Remove the suppression for {}? They will be mailed again.", s.address)) {
                button type="submit" class="text-sm font-medium text-destructive-text hover:underline" { "Remove" }
            }
        }
    }
}

/// Mailer suppression list (BUNYIP-834): every address the mailer relay has
/// stopped sending to, with the reason/detail and a Remove action that lifts
/// the suppression. AdminUser-guarded like the other admin pages; removal is
/// gated on verification, matching the API's audited delete.
pub async fn mailer_suppressions(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::list_mailer_suppressions(&st.api, c.forward.as_deref(), page, 20).await;
    let reachable = data.is_ok();
    let (items, total, total_pages) = match data {
        Ok(p) => (p.items, p.total, p.total_pages),
        Err(_) => (Vec::new(), 0, 1),
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Mailer Suppressions" } p class="mt-2 text-muted-foreground" { "Addresses the mailer relay refuses to send to after a bounce or spam complaint. Removing one lets that address be mailed again." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("shield-off", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Suppressed Addresses" } }
                    @if reachable { p class="text-sm text-muted-foreground" { (total) " total." } }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load mailer suppressions."))
                    } @else if items.is_empty() {
                        (empty_state("shield-off", "No suppressed addresses.", None))
                    } @else {
                        div { @for s in &items { (suppression_row(s)) } }
                        (pager("/admin/mailer-suppressions", "page", page, total_pages))
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/mailer-suppressions",
        "Mailer Suppressions",
        content,
    )
}

/// Lift a suppression (BUNYIP-834), then redirect back to the list with a
/// success/error toast.
pub async fn mailer_suppression_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = verification_gate(&user, &c, "/admin/mailer-suppressions") {
        return refusal;
    }
    let target =
        match admin_api::delete_mailer_suppression(&st.api, c.forward.as_deref(), &address).await {
            Ok(()) => "/admin/mailer-suppressions?toast_ok=Suppression%20removed".to_string(),
            Err(e) => format!(
                "/admin/mailer-suppressions?toast_err={}",
                urlenc(&e.user_message())
            ),
        };
    redirect_cookies(&target, &c.set_cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(detail: Option<&str>) -> MailerSuppression {
        MailerSuppression {
            address: "bounced@example.com".into(),
            reason: "hard_bounce".into(),
            detail: detail.map(|d| d.to_string()),
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn row_shows_address_and_reason() {
        let html = suppression_row(&sample(None)).into_string();
        assert!(html.contains("bounced@example.com"));
        assert!(html.contains("hard_bounce"));
    }

    #[test]
    fn row_shows_detail_when_present() {
        let html = suppression_row(&sample(Some("550 mailbox unavailable"))).into_string();
        assert!(html.contains("550 mailbox unavailable"));
    }

    #[test]
    fn row_offers_remove_action() {
        let html = suppression_row(&sample(None)).into_string();
        assert!(
            html.contains(r#"action="/admin/mailer-suppressions/bounced%40example.com/delete""#)
        );
    }
}
