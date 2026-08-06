//! Admin panel: Dashboard.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::html;

use crate::api::admin as admin_api;
use crate::api::types::DatasetHealth;
use crate::handlers::{admin_guard, admin_response};
use crate::util::rel_time;
use crate::views::ui::{badge, button_class, empty_state, error_box, icon};
use crate::web::AppState;

use super::title_case;

/// One dataset-freshness row (BUNYIP-474). The four states are visually
/// distinct: not configured (muted), configured-but-missing (destructive),
/// stale (warning), and fresh (success), so an admin can tell "we chose not to
/// deploy it" from "it is deployed but overdue" at a glance.
pub(super) fn dataset_row(d: &DatasetHealth) -> maud::Markup {
    let age = d
        .age_days
        .map(|n| format!("{n} day{} old", if n == 1 { "" } else { "s" }));
    html! {
        div class="flex items-center justify-between gap-4 py-2" {
            div class="min-w-0" {
                p class="text-sm font-medium" { (d.name) }
                p class="text-xs text-muted-foreground font-mono" { (d.env_var) }
            }
            div class="flex items-center gap-3 shrink-0" {
                @if let Some(a) = &age { span class="text-xs text-muted-foreground" { (a) } }
                @if !d.configured {
                    (badge("outline", "Not configured"))
                } @else if !d.present {
                    (badge("destructive", "Missing"))
                } @else if d.stale {
                    (badge("warning", "Stale"))
                } @else {
                    (badge("success", "Fresh"))
                }
            }
        }
    }
}

/// The dashboard "Datasets" card: freshness of the offline IP `.BIN` files.
pub(super) fn datasets_card(datasets: &[DatasetHealth]) -> maud::Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Datasets" }
                p class="text-sm text-muted-foreground" { "Offline IP intelligence for login-location and abuse enrichment. Refreshed out of band (see scripts/refresh-ip2-datasets.sh); a stale file keeps working but its data drifts." }
            }
            div class="p-6 pt-0" {
                div class="divide-y" { @for d in datasets { (dataset_row(d)) } }
            }
        }
    }
}

pub async fn dashboard(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let stats = admin_api::stats(&st.api, fwd).await.ok();
    // BUNYIP-474: dataset freshness for the Datasets card. Degrades to no card
    // if the health call fails; it never blocks the dashboard.
    let datasets = admin_api::system_health(&st.api, fwd)
        .await
        .map(|h| h.datasets)
        .unwrap_or_default();
    let logs_data = admin_api::audit_logs(&st.api, fwd, 1, 5, false).await;
    let logs_reachable = logs_data.is_ok();
    let logs = logs_data.map(|p| p.items).unwrap_or_default();
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
                        (icon("layers", "h-5 w-5 text-primary-text mt-0.5"))
                        div class="flex-1" {
                            h3 class="text-lg font-semibold" { "This environment has no applications yet" }
                            p class="text-sm text-muted-foreground mt-1" { "Load a starter template or import your own data to populate the catalog." }
                            a href="/admin/seed" class=(button_class("default", "sm", "mt-3")) { (icon("layers", "mr-2 h-4 w-4")) "Set up seed data" }
                        }
                    }
                }
            }
            @if stats.is_none() {
                (error_box("Could not reach the API."))
            } @else {
                div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4" {
                    (stat("Total Users", stats.as_ref().map(|s| s.total_users.to_string()).unwrap_or_else(|| "0".into()), "Registered accounts", "users"))
                    (stat("Active Memberships", stats.as_ref().map(|s| s.active_members.to_string()).unwrap_or_else(|| "0".into()), "Paying customers", "credit-card"))
                    (stat("Active Apps", stats.as_ref().map(|s| format!("{}/{}", s.active_applications, s.total_applications)).unwrap_or_else(|| "0/0".into()), "Applications online", "trending-up"))
                    (stat("Past Due", stats.as_ref().map(|s| s.past_due_members.to_string()).unwrap_or_else(|| "0".into()), "In grace period", "alert-triangle"))
                }
            }
            @if !datasets.is_empty() { (datasets_card(&datasets)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } p class="text-sm text-muted-foreground" { "Latest platform events" } }
                div class="p-6 pt-0" {
                    @if !logs_reachable { (error_box("Could not reach the API to load recent activity.")) }
                    @else if logs.is_empty() { (empty_state("activity", "No recent activity", None)) }
                    @else {
                        div class="space-y-4" {
                            @for log in &logs {
                                div class="flex items-center gap-3" {
                                    (icon("activity", "h-4 w-4 text-muted-foreground"))
                                    div class="flex-1 min-w-0" { p class="text-sm font-medium truncate" { (title_case(&log.action)) } p class="text-xs text-muted-foreground truncate" { (log.actor_email.clone().unwrap_or_else(|| "System".into())) } }
                                    span class="text-xs text-muted-foreground" { (rel_time(&log.created_at)) }
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

#[cfg(test)]
mod dataset_card_tests {
    use super::*;

    fn ds(
        name: &str,
        configured: bool,
        present: bool,
        age: Option<i64>,
        stale: bool,
    ) -> DatasetHealth {
        DatasetHealth {
            name: name.into(),
            env_var: "X_DB_PATH".into(),
            configured,
            present,
            age_days: age,
            stale,
        }
    }

    #[test]
    fn datasets_card_shows_each_freshness_state() {
        let rows = [
            ds("Fresh one", true, true, Some(3), false),
            ds("Stale one", true, true, Some(90), true),
            ds("Missing one", true, false, None, false),
            ds("Unset one", false, false, None, false),
        ];
        let html = datasets_card(&rows).into_string();
        assert!(html.contains("Datasets"), "card titled");
        assert!(html.contains("3 days old"), "fresh age shown");
        assert!(html.contains(">Fresh<"), "fresh badge");
        assert!(html.contains(">Stale<"), "stale badge");
        assert!(html.contains(">Missing<"), "configured-but-missing badge");
        assert!(html.contains(">Not configured<"), "unconfigured badge");
    }

    #[test]
    fn age_is_singular_for_one_day() {
        let html = datasets_card(&[ds("A", true, true, Some(1), false)]).into_string();
        assert!(html.contains("1 day old") && !html.contains("1 days old"));
    }
}
