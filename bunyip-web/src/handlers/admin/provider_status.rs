//! Admin panel: suite provider status (BUNYIP-634).
//!
//! One page shows every application in the suite's live provider state,
//! Bunyip's own included, through the shared contract
//! (`docs/provider-status-contract.md`): which providers are enabled, which
//! is serving, and the discrepancies that matter, flagged rather than left
//! for the reader to notice by comparing columns. The classification is
//! bunyip-api's (`GET /v1/admin/providers/status`); this page only renders
//! it, following the System Status page's shape (BUNYIP-546): a failed fetch
//! is stated inside the card rather than hidden.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::api::admin as admin_api;
use crate::api::types::{
    ProviderAppState, ProviderAppStatusRow, ProviderDiscrepancy, ProviderKindEntry,
    ProviderStatusReport,
};
use crate::handlers::{admin_guard, admin_response};
use crate::views::ui::{badge, error_box};

/// The badge for one application's state.
fn state_badge(status: &ProviderAppState) -> Markup {
    match status {
        ProviderAppState::Ok { .. } => badge("success", "Reachable"),
        ProviderAppState::Unreachable { .. } => badge("destructive", "Unreachable"),
        ProviderAppState::Unauthenticated => badge("destructive", "Unauthenticated"),
        ProviderAppState::VersionMismatch { .. } => badge("outline", "Version mismatch"),
        ProviderAppState::Unknown => badge("outline", "Unknown"),
    }
}

/// The failure detail line for a non-healthy row. Empty for a healthy one
/// (the caller skips rendering it).
fn state_detail(status: &ProviderAppState) -> Option<String> {
    match status {
        ProviderAppState::Ok { .. } => None,
        ProviderAppState::Unreachable { reason } => Some(reason.clone()),
        ProviderAppState::Unauthenticated => {
            Some("the application rejected Bunyip's machine credential".to_string())
        }
        ProviderAppState::VersionMismatch { reported_version } => Some(format!(
            "the application reports contract version {reported_version:?}, which this Bunyip does not understand"
        )),
        ProviderAppState::Unknown => Some("an unrecognised status was returned".to_string()),
    }
}

/// One provider kind's row within a healthy application: which providers are
/// enabled, in priority order, and which is serving.
fn kind_row(kind: &ProviderKindEntry) -> Markup {
    html! {
        div class="py-2" {
            div class="flex items-center justify-between gap-4" {
                p class="text-sm font-medium" { (kind.kind) }
                @if let Some(serving) = &kind.serving {
                    span class="text-xs text-muted-foreground" { "serving: " (serving) }
                } @else {
                    span class="text-xs text-muted-foreground" { "nothing is serving" }
                }
            }
            @if !kind.enabled.is_empty() {
                p class="text-xs text-muted-foreground mt-1" {
                    "enabled: "
                    @for (i, provider) in kind.enabled.iter().enumerate() {
                        @if i > 0 { ", " }
                        (provider.name)
                        @if !provider.reachable { " (unreachable)" }
                    }
                }
            }
        }
    }
}

/// The report, when this row's state is healthy. A plain function rather than
/// matching the struct-shaped `Ok { report }` variant inline in a maud
/// template, whose `{ ... }` pattern braces the `html!` macro parser cannot
/// tell apart from a template block.
fn ok_report(status: &ProviderAppState) -> Option<&ProviderStatusReport> {
    match status {
        ProviderAppState::Ok { report } => Some(report),
        _ => None,
    }
}

/// One application's card.
fn app_card(row: &ProviderAppStatusRow) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center justify-between gap-4" {
                    h3 class="text-xl font-semibold leading-none tracking-tight" { (row.app) }
                    span class="shrink-0" { (state_badge(&row.status)) }
                }
            }
            div class="p-6 pt-0" {
                @if let Some(detail) = state_detail(&row.status) {
                    p class="text-sm text-muted-foreground" { (detail) }
                } @else if let Some(report) = ok_report(&row.status) {
                    div class="divide-y" { @for kind in &report.kinds { (kind_row(kind)) } }
                }
            }
        }
    }
}

/// One flagged discrepancy line.
fn discrepancy_row(d: &ProviderDiscrepancy) -> Markup {
    let text = match d {
        ProviderDiscrepancy::DeclaredProviderHoldsNothing { app, kind, key } => {
            format!("{app}/{kind}: \"{key}\" is held by no provider")
        }
        ProviderDiscrepancy::PresentInMultipleProviders {
            app,
            kind,
            key,
            providers,
        } => {
            let providers = providers.join(", ");
            if key.is_empty() {
                format!("{app}/{kind}: more than one provider holds a value ({providers})")
            } else {
                format!("{app}/{kind}: \"{key}\" is present in more than one provider ({providers})")
            }
        }
        ProviderDiscrepancy::AbsentFromHighestPriorityProvider {
            app,
            kind,
            key,
            serving,
            holder,
        } => format!(
            "{app}/{kind}: \"{key}\" is absent from {serving} (the highest-priority provider) but held by {holder}"
        ),
        ProviderDiscrepancy::Unknown => "an unrecognised discrepancy was reported".to_string(),
    };
    html! {
        li class="text-sm" { (text) }
    }
}

fn discrepancies_card(discrepancies: &[ProviderDiscrepancy]) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Discrepancies" }
                p class="text-sm text-muted-foreground" { "Conditions worth a second look, flagged so nobody has to notice them by comparing columns." }
            }
            div class="p-6 pt-0" {
                @if discrepancies.is_empty() {
                    p class="text-sm text-muted-foreground" { "None flagged." }
                } @else {
                    ul class="space-y-2 list-disc pl-5" { @for d in discrepancies { (discrepancy_row(d)) } }
                }
            }
        }
    }
}

fn provider_status_content(
    apps: &[ProviderAppStatusRow],
    discrepancies: &[ProviderDiscrepancy],
    reachable: bool,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Provider Status" } p class="mt-2 text-muted-foreground" { "The live provider state of every application in the suite, Bunyip's own included." } }
            @if !reachable {
                (error_box("Could not reach the API to load the suite provider status."))
            } @else {
                (discrepancies_card(discrepancies))
                div class="grid gap-4 md:grid-cols-2" { @for row in apps { (app_card(row)) } }
            }
        }
    }
}

/// GET /admin/providers/status
pub async fn provider_status_page(
    State(st): State<crate::web::AppState>,
    headers: HeaderMap,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fetched = admin_api::provider_status(&st.api, c.forward.as_deref()).await;
    let reachable = fetched.is_ok();
    let aggregate = fetched.unwrap_or_default();
    let content = provider_status_content(&aggregate.apps, &aggregate.discrepancies, reachable);
    admin_response(
        &c,
        &user,
        "/admin/providers/status",
        "Provider Status",
        content,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::ProviderStatusReport;

    fn ok_row(app: &str) -> ProviderAppStatusRow {
        ProviderAppStatusRow {
            app: app.to_string(),
            status: ProviderAppState::Ok {
                report: ProviderStatusReport {
                    hosting_profile: app.to_string(),
                    kinds: vec![ProviderKindEntry {
                        kind: "secrets_application".to_string(),
                        serving: Some("environment".to_string()),
                        enabled: vec![],
                        keys: vec![],
                    }],
                    collected_at: None,
                },
            },
        }
    }

    #[test]
    fn each_state_renders_its_own_badge() {
        let ok = ok_row("bunyip");
        let unreachable = ProviderAppStatusRow {
            app: "mokosh".to_string(),
            status: ProviderAppState::Unreachable {
                reason: "timed out".to_string(),
            },
        };
        let unauth = ProviderAppStatusRow {
            app: "drillmark".to_string(),
            status: ProviderAppState::Unauthenticated,
        };
        let html = provider_status_content(&[ok, unreachable, unauth], &[], true).into_string();
        assert!(html.contains(">Reachable<"));
        assert!(html.contains(">Unreachable<"));
        assert!(html.contains(">Unauthenticated<"));
        assert!(html.contains("timed out"));
    }

    /// BUNYIP-546 shape: an unreachable API is stated inside the page rather
    /// than an empty page that reads as "everything is fine".
    #[test]
    fn an_unreachable_api_is_stated_on_the_page() {
        let html = provider_status_content(&[], &[], false).into_string();
        assert!(html.contains("Could not reach the API to load the suite provider status."));
    }

    /// Never omitted: every application row given renders, whatever its state.
    #[test]
    fn every_application_row_renders_never_omitted() {
        let rows = vec![
            ok_row("bunyip"),
            ProviderAppStatusRow {
                app: "mokosh".to_string(),
                status: ProviderAppState::VersionMismatch {
                    reported_version: "2".to_string(),
                },
            },
            ProviderAppStatusRow {
                app: "drillmark".to_string(),
                status: ProviderAppState::Unknown,
            },
        ];
        let html = provider_status_content(&rows, &[], true).into_string();
        assert!(html.contains("bunyip"));
        assert!(html.contains("mokosh"));
        assert!(html.contains("drillmark"));
        assert!(html.contains("Version mismatch"));
    }

    #[test]
    fn discrepancies_render_when_present_and_say_none_when_absent() {
        let none = discrepancies_card(&[]).into_string();
        assert!(none.contains("None flagged."));

        let flagged =
            discrepancies_card(&[ProviderDiscrepancy::AbsentFromHighestPriorityProvider {
                app: "bunyip".to_string(),
                kind: "secrets_application".to_string(),
                key: "SMTP_PASSWORD".to_string(),
                serving: "database".to_string(),
                holder: "environment".to_string(),
            }])
            .into_string();
        assert!(flagged.contains("SMTP_PASSWORD"));
        assert!(flagged.contains("database"));
        assert!(flagged.contains("environment"));
    }
}
