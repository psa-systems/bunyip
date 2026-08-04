//! Admin panel: Dashboard.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::html;

use crate::api::admin as admin_api;
use crate::handlers::{admin_guard, admin_response};
use crate::util::relative_time;
use crate::views::ui::{button_class, icon};
use crate::web::AppState;

use super::title_case;

pub async fn dashboard(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let stats = admin_api::stats(&st.api, fwd).await.ok();
    let logs = admin_api::audit_logs(&st.api, fwd, 1, 5, false)
        .await
        .map(|p| p.items)
        .unwrap_or_default();
    // Only prompt when we positively know the catalog is empty (stats fetched
    // and zero apps), not when the stats call failed (PSA-57).
    let catalog_empty = stats
        .as_ref()
        .map(|s| s.total_applications == 0)
        .unwrap_or(false);

    let stat = |label: &str, value: String, sub: &str, ic: &str| {
        html! {
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 flex-row items-center justify-between pb-2" {
                    h3 class="text-sm font-medium" { (label) } (icon(ic, "h-4 w-4 text-muted-foreground"))
                }
                div class="p-6 pt-0" { div class="text-2xl font-bold" { (value) } p class="text-xs text-muted-foreground" { (sub) } }
            }
        }
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Admin Dashboard" } p class="mt-2 text-muted-foreground" { "Overview of your platform." } }
            @if catalog_empty {
                div class="rounded-lg border border-primary/30 bg-primary/5 p-6" {
                    div class="flex items-start gap-3" {
                        (icon("layers", "h-5 w-5 text-primary mt-0.5"))
                        div class="flex-1" {
                            h3 class="text-lg font-semibold" { "This environment has no applications yet" }
                            p class="text-sm text-muted-foreground mt-1" { "Load a starter template or import your own data to populate the catalog." }
                            a href="/admin/seed" class=(button_class("default", "sm", "mt-3")) { (icon("layers", "mr-2 h-4 w-4")) "Set up seed data" }
                        }
                    }
                }
            }
            div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4" {
                (stat("Total Users", stats.as_ref().map(|s| s.total_users.to_string()).unwrap_or_else(|| "0".into()), "Registered accounts", "users"))
                (stat("Active Memberships", stats.as_ref().map(|s| s.active_members.to_string()).unwrap_or_else(|| "0".into()), "Paying customers", "credit-card"))
                (stat("Active Apps", stats.as_ref().map(|s| format!("{}/{}", s.active_applications, s.total_applications)).unwrap_or_else(|| "0/0".into()), "Applications online", "trending-up"))
                (stat("Past Due", stats.as_ref().map(|s| s.past_due_members.to_string()).unwrap_or_else(|| "0".into()), "In grace period", "alert-triangle"))
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } p class="text-sm text-muted-foreground" { "Latest platform events" } }
                div class="p-6 pt-0" {
                    @if logs.is_empty() { p class="text-muted-foreground text-center py-8" { "No recent activity" } }
                    @else {
                        div class="space-y-4" {
                            @for log in &logs {
                                div class="flex items-center gap-3" {
                                    (icon("activity", "h-4 w-4 text-muted-foreground"))
                                    div class="flex-1 min-w-0" { p class="text-sm font-medium truncate" { (title_case(&log.action)) } p class="text-xs text-muted-foreground truncate" { (log.actor_email.clone().unwrap_or_else(|| "System".into())) } }
                                    span class="text-xs text-muted-foreground" { (relative_time(&log.created_at)) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin", "Admin · Bunyip", content)
}
