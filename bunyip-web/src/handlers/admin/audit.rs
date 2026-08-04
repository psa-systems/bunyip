//! Admin panel: Audit logs.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::AdminAuditLog;
use crate::handlers::{admin_guard, admin_response};
use crate::util::relative_time;
use crate::views::ui::{badge, button_class, error_box, icon};
use crate::web::AppState;

use super::{pager, title_case};

#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub admin_only: Option<String>,
}

fn audit_row(log: &AdminAuditLog) -> Markup {
    let ic = match log.action.as_str() {
        a if a.contains("login") => "log-in",
        a if a.contains("membership") || a.contains("payment") => "credit-card",
        a if a.contains("password") => "key",
        a if a.contains("magic_link") => "mail",
        a if a.contains("register") => "user-plus",
        a if a.contains("admin") || a.contains("deactivate") => "shield",
        _ => "user",
    };
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4" {
                div class="flex h-10 w-10 items-center justify-center rounded-full bg-muted" { (icon(ic, "h-5 w-5 text-muted-foreground")) }
                div {
                    div class="flex items-center gap-2" {
                        p class="font-medium" { (title_case(&log.action)) }
                        @if log.is_admin_action { (badge("default", "Admin")) }
                        @if log.severity == "warning" { (badge("warning", "Warning")) }
                        @if log.severity == "error" { (badge("destructive", "Error")) }
                    }
                    p class="text-sm text-muted-foreground" {
                        (log.actor_email.clone().unwrap_or_else(|| "System".into()))
                        @if let Some(ip) = &log.actor_ip_address { " • " (ip) }
                    }
                }
            }
            p class="text-sm text-muted-foreground whitespace-nowrap" { (relative_time(&log.created_at)) }
        }
    }
}

pub async fn audit_logs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let admin_only = q.admin_only.as_deref() == Some("true");
    let data = admin_api::audit_logs(&st.api, c.forward.as_deref(), page, 50, admin_only)
        .await
        .ok();
    let reachable = data.is_some();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = if admin_only {
        "/admin/audit-logs?admin_only=true"
    } else {
        "/admin/audit-logs"
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Audit Logs" } p class="mt-2 text-muted-foreground" { "View security events and user activity." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between" {
                        div class="flex items-center gap-3" { (icon("file-text", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } }
                        div class="flex items-center gap-2 text-sm" {
                            @if admin_only { a href="/admin/audit-logs" class=(button_class("secondary", "sm", "")) { "Showing: Admin only" } }
                            @else { a href="/admin/audit-logs?admin_only=true" class=(button_class("outline", "sm", "")) { "Admin actions only" } }
                        }
                    }
                }
                div class="p-6 pt-0" {
                    @if !reachable { (error_box("Could not reach the API to load audit logs.")) }
                    @else if items.is_empty() { p class="text-center text-muted-foreground py-8" { "No audit logs found" } }
                    @else { div class="space-y-0" { @for log in &items { (audit_row(log)) } } }
                    (pager(base, page, total_pages))
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/audit-logs",
        "Audit Logs · Bunyip",
        content,
    )
}
