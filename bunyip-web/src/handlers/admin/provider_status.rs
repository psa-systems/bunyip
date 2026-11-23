//! Admin panel: suite provider status (BUNYIP-634).
//!
//! One page shows every application in the suite's live provider state,
//! this deployment's own included, through the shared contract
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

use bunyip_domain::services::provider_status::{EnabledProviderReport, KindEnumerationStatus};

use crate::api::admin as admin_api;
use crate::api::types::{
    ProviderAppState, ProviderAppStatusRow, ProviderDiscrepancy, ProviderKindEntry,
    ProviderStatusReport,
};
use crate::api::ApiError;
use crate::handlers::{admin_guard, admin_response};
use crate::views::ui::{badge, empty_state, error_box_for};

// SPEC-12.19.5
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

// SPEC-12.19.5
/// The failure detail line for a non-healthy row. Empty for a healthy one
/// (the caller skips rendering it).
fn state_detail(status: &ProviderAppState, brand_name: &str) -> Option<String> {
    let this_deployment = if brand_name.is_empty() {
        "this deployment".to_string()
    } else {
        brand_name.to_string()
    };
    match status {
        ProviderAppState::Ok { .. } => None,
        ProviderAppState::Unreachable { reason } => Some(reason.clone()),
        ProviderAppState::Unauthenticated => Some(format!(
            "the application rejected {this_deployment}'s machine credential"
        )),
        ProviderAppState::VersionMismatch { reported_version } => Some(format!(
            "the application reports contract version {reported_version:?}, which {this_deployment} does not understand"
        )),
        ProviderAppState::Unknown => Some("an unrecognised status was returned".to_string()),
    }
}

// SPEC-12.19.5
/// One provider kind's row within a healthy application: which providers are
/// enabled, in priority order, and which is serving.
///
/// BUNYIP-664: each enabled provider renders as a chip whose `title` tooltip
/// carries the aggregator's per-provider detail (priority + reachability +
/// unreachable reason). Keeps the visible chip compact; the detail is one
/// hover away. `aria-label` carries the same text so screen readers do not
/// miss the detail a sighted user gets through `title`.
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
                p class="text-xs text-muted-foreground mt-1 flex flex-wrap gap-1 items-center" {
                    span { "enabled:" }
                    @for provider in &kind.enabled {
                        (provider_chip(provider))
                    }
                }
            }
            (enumeration_line(kind.enumeration.as_ref()))
        }
    }
}

/// BUNYIP-664: one enabled provider rendered as a chip with its tooltip
/// detail. The tooltip string is pure data - name, priority, reachability,
/// reason - assembled here so a test can assert its exact shape.
fn provider_chip(provider: &EnabledProviderReport) -> Markup {
    let detail = provider_tooltip_detail(provider);
    html! {
        span
            class="inline-flex items-center rounded border border-border/60 bg-muted/50 px-1.5 py-0.5"
            title=(detail)
            aria-label=(detail)
        {
            (provider.name)
            @if !provider.reachable { " *" }
        }
    }
}

/// BUNYIP-664: pure classifier the tooltip + its test both read from. The
/// aggregator never carries a credential-shaped value, so the string here
/// cannot grow one by mistake: this is names, small integers and a free-text
/// reason the aggregator itself wrote.
pub(super) fn provider_tooltip_detail(provider: &EnabledProviderReport) -> String {
    let reachable = if provider.reachable {
        "reachable"
    } else {
        "unreachable"
    };
    let base = format!("priority {}; {}", provider.priority, reachable);
    match (&provider.reachable, &provider.unreachable_reason) {
        (false, Some(reason)) if !reason.is_empty() => format!("{base}: {reason}"),
        _ => base,
    }
}

/// BUNYIP-664: `enumeration: Supported (N keys)` / `Unsupported` under the
/// enabled chips; absent when the aggregator did not report a status. The
/// Supported vector itself holds key names only (the contract redacts
/// values), so a count is safe to surface without exposing the names.
fn enumeration_line(status: Option<&KindEnumerationStatus>) -> Markup {
    match status {
        None => html! {},
        Some(KindEnumerationStatus::Supported(keys)) => {
            let n = keys.len();
            let suffix = if n == 1 { "key" } else { "keys" };
            html! {
                p class="text-xs text-muted-foreground mt-1" {
                    "enumeration: Supported (" (n) " " (suffix) ")"
                }
            }
        }
        Some(KindEnumerationStatus::Unsupported) => html! {
            p class="text-xs text-muted-foreground mt-1" { "enumeration: Unsupported" }
        },
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

// SPEC-12.19.5
/// One application's card.
fn app_card(row: &ProviderAppStatusRow, brand_name: &str) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center justify-between gap-4" {
                    h3 class="text-xl font-semibold leading-none tracking-tight" { (row.app) }
                    span class="shrink-0" { (state_badge(&row.status)) }
                }
            }
            div class="p-6 pt-0" {
                @if let Some(detail) = state_detail(&row.status, brand_name) {
                    p class="text-sm text-muted-foreground" { (detail) }
                } @else if let Some(report) = ok_report(&row.status) {
                    div class="divide-y" { @for kind in &report.kinds { (kind_row(kind)) } }
                }
            }
        }
    }
}

// SPEC-12.19.6
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

// SPEC-12.19.4
fn discrepancies_card(discrepancies: &[ProviderDiscrepancy]) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Discrepancies" }
                p class="text-sm text-muted-foreground" { "Conditions worth a second look, flagged so nobody has to notice them by comparing columns." }
            }
            div class="p-6 pt-0" {
                @if discrepancies.is_empty() {
                    (empty_state("circle-check", "None flagged.", None))
                } @else {
                    ul class="space-y-2 list-disc pl-5" { @for d in discrepancies { (discrepancy_row(d)) } }
                }
            }
        }
    }
}

// SPEC-12.19.7
/// The intro sentence under the page heading. Empty brand name omits the
/// possessive clause rather than substituting a literal.
fn intro_note(brand_name: &str) -> String {
    if brand_name.is_empty() {
        "The live provider state of every application in the suite, including this deployment's own.".to_string()
    } else {
        format!(
            "The live provider state of every application in the suite, {brand_name}'s own included."
        )
    }
}

// SPEC-12.19.4: a failed fetch is stated in the page, never an empty page
fn provider_status_content(
    apps: &[ProviderAppStatusRow],
    discrepancies: &[ProviderDiscrepancy],
    fetch_error: Option<&ApiError>,
    brand_name: &str,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Provider Status" } p class="mt-2 text-muted-foreground" { (intro_note(brand_name)) } }
            @if let Some(e) = fetch_error {
                (error_box_for("Could not reach the API to load the suite provider status.", e))
            } @else {
                (discrepancies_card(discrepancies))
                div class="grid gap-4 md:grid-cols-2" { @for row in apps { (app_card(row, brand_name)) } }
            }
        }
    }
}

// SPEC-12.19.4
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
    let fetch_error = fetched.as_ref().err().cloned();
    let aggregate = fetched.unwrap_or_default();
    let content = provider_status_content(
        &aggregate.apps,
        &aggregate.discrepancies,
        fetch_error.as_ref(),
        &crate::views::layout::brand_name(),
    );
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

    fn load_error() -> ApiError {
        ApiError {
            status: 500,
            code: "INTERNAL_ERROR".into(),
            message: "Failed to load provider status".into(),
            retry_after: None,
            request_id: Some("req_abc123".into()),
            bucket: None,
        }
    }

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
                        ..Default::default()
                    }],
                    ..Default::default()
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
        let html = provider_status_content(&[ok, unreachable, unauth], &[], None, "").into_string();
        assert!(html.contains(">Reachable<"));
        assert!(html.contains(">Unreachable<"));
        assert!(html.contains(">Unauthenticated<"));
        assert!(html.contains("timed out"));
    }

    /// BUNYIP-546 shape: an unreachable API is stated inside the page rather
    /// than an empty page that reads as "everything is fine".
    #[test]
    fn an_unreachable_api_is_stated_on_the_page() {
        let err = load_error();
        let html = provider_status_content(&[], &[], Some(&err), "").into_string();
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
        let html = provider_status_content(&rows, &[], None, "").into_string();
        assert!(html.contains("bunyip"));
        assert!(html.contains("mokosh"));
        assert!(html.contains("drillmark"));
        assert!(html.contains("Version mismatch"));
    }

    /// BUNYIP-664 AC #2: the aggregator's per-provider detail (priority +
    /// reachability + reason) reaches the page as a `title` tooltip on each
    /// chip; a screen-reader user gets it through `aria-label` too.
    #[test]
    fn each_enabled_provider_chip_carries_its_tooltip_detail() {
        let kind = ProviderKindEntry {
            kind: "secrets_application".to_string(),
            serving: Some("database".to_string()),
            enabled: vec![
                EnabledProviderReport {
                    name: "database".to_string(),
                    priority: 1,
                    reachable: true,
                    unreachable_reason: None,
                },
                EnabledProviderReport {
                    name: "environment".to_string(),
                    priority: 2,
                    reachable: false,
                    unreachable_reason: Some("could not read $SMTP_PASSWORD".to_string()),
                },
            ],
            keys: vec![],
            ..Default::default()
        };
        let html = kind_row(&kind).into_string();
        assert!(
            html.contains(r#"title="priority 1; reachable""#),
            "reachable provider carries its priority + reachable title: {html}"
        );
        assert!(
            html.contains(r#"aria-label="priority 1; reachable""#),
            "reachable provider carries its aria-label too: {html}"
        );
        assert!(
            html.contains(r#"title="priority 2; unreachable: could not read $SMTP_PASSWORD""#),
            "unreachable provider carries its reason in the title: {html}"
        );
        // The chip is still visible as its name; the `*` marker calls out
        // unreachable without hiding what's broken.
        assert!(html.contains("environment"));
        assert!(html.contains('*'));
    }

    /// BUNYIP-664 AC #2: the enumeration status line surfaces alongside the
    /// chips when the aggregator reports one, counting keys without naming
    /// them (the contract redacts values; name-only would still have been a
    /// data leak choice).
    #[test]
    fn enumeration_status_renders_a_count_without_naming_keys() {
        let supported = ProviderKindEntry {
            kind: "configuration".to_string(),
            serving: Some("environment".to_string()),
            enabled: vec![],
            keys: vec![],
            enumeration: Some(KindEnumerationStatus::Supported(vec![
                "APP_URL".into(),
                "COOKIE_DOMAIN".into(),
                "DATABASE_URL".into(),
            ])),
        };
        let html = kind_row(&supported).into_string();
        assert!(
            html.contains("enumeration: Supported (3 keys)"),
            "Supported renders a count: {html}"
        );
        for leaked in ["APP_URL", "COOKIE_DOMAIN", "DATABASE_URL"] {
            assert!(
                !html.contains(leaked),
                "enumeration keys must not leak into the page: {leaked} in {html}"
            );
        }

        let unsupported = ProviderKindEntry {
            enumeration: Some(KindEnumerationStatus::Unsupported),
            ..Default::default()
        };
        let html = kind_row(&unsupported).into_string();
        assert!(html.contains("enumeration: Unsupported"));

        let absent = ProviderKindEntry::default();
        let html = kind_row(&absent).into_string();
        assert!(!html.contains("enumeration:"));
    }

    /// BUNYIP-664 AC #5 (redaction): the page's rendered markup must not carry
    /// any credential-shaped substring the aggregator's contract already
    /// forbids on the wire. Belt-and-braces: the aggregator itself guards the
    /// envelope (`no_value_shaped_field_in_the_contract`), this test guards
    /// against a render-side mistake.
    #[test]
    fn rendered_page_carries_no_credential_shaped_substring() {
        let rows = vec![ok_row("bunyip")];
        let html = provider_status_content(&rows, &[], None, "").into_string();
        for forbidden in [
            "client_secret",
            "password=",
            "api_token",
            "secret_key",
            "oauth_token",
            "salt=",
            "nonce=",
        ] {
            assert!(
                !html.contains(forbidden),
                "redaction: rendered page carries a credential-shaped substring {forbidden:?}: {html}"
            );
        }
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
