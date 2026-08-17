//! Admin panel: Dashboard.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::html;

use crate::api::admin as admin_api;
use crate::api::types::{AdminStatsResponse, DatasetHealth};
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
/// BUNYIP-546: the card renders on every load. Hiding it when the list was
/// empty erased the very distinction `dataset_row`'s four badges exist to draw,
/// and hiding it when the health call failed made a broken dashboard look like
/// a healthy one, so both states are stated inside the card instead.
pub(super) fn datasets_card(datasets: &[DatasetHealth], reachable: bool) -> maud::Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Datasets" }
                p class="text-sm text-muted-foreground" { "Offline IP intelligence for login-location and abuse enrichment. Refreshed out of band (see scripts/refresh-ip2-datasets.nu); a stale file keeps working but its data drifts." }
            }
            div class="p-6 pt-0" {
                @if !reachable {
                    (error_box("Could not reach the API to load dataset health."))
                } @else if datasets.is_empty() {
                    (empty_state("package", "No datasets are configured.", None))
                } @else {
                    div class="divide-y" { @for d in datasets { (dataset_row(d)) } }
                }
            }
        }
    }
}

/// The four platform-stat tiles. Pure so the card container is unit-testable
/// (like `datasets_card` above). BUNYIP-367: the grid was `gap-4` while every
/// other card grid in the authenticated shells is `gap-6`, so the tiles sat a
/// third closer together than the cards below them.
pub(super) fn stats_grid(s: &AdminStatsResponse) -> maud::Markup {
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
    html! {
        div class="grid gap-6 md:grid-cols-2 lg:grid-cols-4" {
            (stat("Total Users", s.total_users.to_string(), "Registered accounts", "users"))
            (stat("Active Memberships", s.active_members.to_string(), "Paying customers", "credit-card"))
            (stat("Active Apps", format!("{}/{}", s.active_applications, s.total_applications), "Applications online", "trending-up"))
            (stat("Past Due", s.past_due_members.to_string(), "In grace period", "alert-triangle"))
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
    // BUNYIP-474: dataset freshness for the Datasets card. BUNYIP-546: the card
    // always renders and says which of the three states it is in; a failed
    // health call still never blocks the dashboard.
    let health = admin_api::system_health(&st.api, fwd).await;
    let datasets_reachable = health.is_ok();
    let datasets = health.map(|h| h.datasets).unwrap_or_default();
    let logs_data = admin_api::audit_logs(&st.api, fwd, 1, 5, false).await;
    let logs_reachable = logs_data.is_ok();
    let logs = logs_data.map(|p| p.items).unwrap_or_default();
    // Only prompt when we positively know the catalog is empty (stats fetched
    // and zero apps), not when the stats call failed (PSA-57).
    let catalog_empty = stats
        .as_ref()
        .map(|s| s.total_applications == 0)
        .unwrap_or(false);

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
            @if let Some(s) = &stats {
                (stats_grid(s))
            } @else {
                (error_box("Could not reach the API."))
            }
            (datasets_card(&datasets, datasets_reachable))
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
    admin_response(&c, &user, "/admin", "Admin Dashboard", content)
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
        let html = datasets_card(&rows, true).into_string();
        assert!(html.contains("Datasets"), "card titled");
        assert!(html.contains("3 days old"), "fresh age shown");
        assert!(html.contains(">Fresh<"), "fresh badge");
        assert!(html.contains(">Stale<"), "stale badge");
        assert!(html.contains(">Missing<"), "configured-but-missing badge");
        assert!(html.contains(">Not configured<"), "unconfigured badge");
    }

    /// BUNYIP-367: the stat tiles are cards, so their grid carries the same
    /// 24px rhythm as every other card container in the admin shell.
    #[test]
    fn stat_tiles_are_spaced_on_the_page_rhythm() {
        let html = stats_grid(&AdminStatsResponse {
            total_users: 12,
            active_members: 7,
            past_due_members: 1,
            grace_period_members: 0,
            total_applications: 4,
            active_applications: 3,
        })
        .into_string();
        crate::views::ui::assert_cards_are_spaced(&html);
        assert!(
            html.contains("grid gap-6"),
            "24px rhythm, not gap-4: {html}"
        );
    }

    #[test]
    fn age_is_singular_for_one_day() {
        let html = datasets_card(&[ds("A", true, true, Some(1), false)], true).into_string();
        assert!(html.contains("1 day old") && !html.contains("1 days old"));
    }

    /// BUNYIP-546 (F14): no dataset configured is a state the operator has to
    /// be able to read, not a reason to drop the card off the page.
    #[test]
    fn datasets_card_states_an_empty_list_inside_the_card() {
        let html = datasets_card(&[], true).into_string();
        assert!(html.contains("Datasets"), "card still renders");
        assert!(
            html.contains("No datasets are configured."),
            "shared empty state inside the card: {html}"
        );
        assert!(
            !html.contains("Could not reach"),
            "empty is not an error: {html}"
        );
    }

    /// BUNYIP-546 (F1): a failed `system_health` call is distinct from an empty
    /// list, and neither hides the card.
    #[test]
    fn datasets_card_distinguishes_an_unreachable_api_from_an_empty_list() {
        let html = datasets_card(&[], false).into_string();
        assert!(html.contains("Datasets"), "card still renders");
        assert!(
            html.contains("Could not reach the API to load dataset health."),
            "error box on a failed fetch: {html}"
        );
        assert!(
            !html.contains("No datasets are configured."),
            "a failed fetch never claims the list is empty: {html}"
        );
    }
}
