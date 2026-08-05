//! Admin panel: Error Log (BUNYIP-327).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::AdminErrorLog;
use crate::handlers::{admin_guard, admin_response};
use crate::util::rel_time;
use crate::views::ui::{badge, button_class, empty_state, error_box, icon};
use crate::web::AppState;

#[derive(Deserialize)]
pub struct LogsQuery {
    pub category: Option<String>,
}

/// Render a single captured ERROR entry: message + category/level badges, the
/// route/client attribution line, and any extra structured fields.
pub(super) fn log_row(e: &AdminErrorLog) -> Markup {
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10" { (icon("alert-triangle", "h-5 w-5 text-destructive")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium break-words" { (e.message) }
                        (badge("destructive", "Error"))
                        @if let Some(cat) = &e.category { (badge("warning", cat)) }
                    }
                    p class="text-sm text-muted-foreground break-words" {
                        span class="font-mono" { (e.target) }
                        @if let Some(r) = &e.route { " • " (r) }
                        @if let Some(cl) = &e.client { " • client " span class="font-medium text-foreground" { (cl) } }
                    }
                    @if !e.fields.is_empty() {
                        p class="text-xs text-muted-foreground mt-1 font-mono break-words" {
                            @for (k, v) in &e.fields { (k) "=" (v) "  " }
                        }
                    }
                }
            }
            p class="text-sm text-muted-foreground whitespace-nowrap" { (rel_time(&e.timestamp)) }
        }
    }
}

/// Admin error-log view (BUNYIP-327): newest-first ERROR events from the API's
/// in-memory ring buffer, filterable by category. Warnings never appear (the
/// buffer captures ERROR only).
pub async fn logs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let category = q
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let data = admin_api::error_logs(&st.api, c.forward.as_deref(), category)
        .await
        .ok();
    let entries = data.as_ref().map(|d| d.entries.clone()).unwrap_or_default();
    let matched = data.as_ref().map(|d| d.matched).unwrap_or(0);
    let buffered = data.as_ref().map(|d| d.buffered).unwrap_or(0);
    let capacity = data.as_ref().map(|d| d.capacity).unwrap_or(0);
    let reachable = data.is_some();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Error Logs" } p class="mt-2 text-muted-foreground" { "Live ERROR-level events from the API, held in memory and rotated (newest first). Warnings are excluded." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between gap-4 flex-wrap" {
                        div class="flex items-center gap-3" { (icon("alert-triangle", "h-5 w-5 text-destructive")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Captured Errors" } }
                        div class="flex items-center gap-2 text-sm" {
                            a href="/admin/logs" class=(button_class(if category.is_none() { "secondary" } else { "outline" }, "sm", "")) { "All" }
                            a href="/admin/logs?category=rate_limit" class=(button_class(if category == Some("rate_limit") { "secondary" } else { "outline" }, "sm", "")) { "Rate limit" }
                        }
                    }
                    @if reachable {
                        p class="text-sm text-muted-foreground" { "Showing " (matched) " of " (buffered) " buffered (capacity " (capacity) ")." }
                    }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load error logs."))
                    } @else if entries.is_empty() {
                        (empty_state("alert-triangle", &format!("No errors captured{}.", if category.is_some() { " in this category" } else { "" }), None))
                    } @else {
                        div class="space-y-0" { @for e in &entries { (log_row(e)) } }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/logs", "Error Logs · Bunyip", content)
}
