//! Admin panel: System Status (BUNYIP-623).
//!
//! A self-hosted deployment starts with every integration switched off and stays
//! usable; this page lists each integration's Configured / Unconfigured / Failing
//! state so a degraded capability is visible and named rather than inferred from
//! a failure. The classification is bunyip-api's (`GET /v1/admin/integrations`,
//! sourced from the BUNYIP-537 startup inventory and `GovernedSecret::feature`);
//! this page only renders it, following the admin dashboard's Datasets card.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::api::admin as admin_api;
use crate::api::types::{ApiVersion, IntegrationState, IntegrationStatus, SystemHealth};
use crate::api::ApiError;
use crate::handlers::{admin_guard, admin_response};
use crate::views::ui::{badge, error_box_for};

/// The badge for one integration state, reusing the dashboard's colour language:
/// success (green) configured, outline (muted) unconfigured, destructive (red)
/// failing. An unrecognised wire value renders muted and asserts nothing.
fn state_badge(state: &IntegrationState) -> Markup {
    match state {
        IntegrationState::Configured => badge("success", "Configured"),
        IntegrationState::Unconfigured => badge("outline", "Unconfigured"),
        IntegrationState::Failing => badge("destructive", "Failing"),
        IntegrationState::Unknown => badge("outline", "Unknown"),
    }
}

/// One integration row: name and state badge on one line, the reason below, and
/// the remedy (present only when it is not already configured) below that.
fn integration_row(s: &IntegrationStatus) -> Markup {
    html! {
        div class="py-3" {
            div class="flex items-center justify-between gap-4" {
                p class="text-sm font-medium" { (s.name) }
                span class="shrink-0" { (state_badge(&s.state)) }
            }
            @if !s.detail.is_empty() {
                p class="text-sm text-muted-foreground mt-1" { (s.detail) }
            }
            @if !s.remedy.is_empty() {
                p class="text-xs text-muted-foreground mt-1" { (s.remedy) }
            }
        }
    }
}

/// The Integrations card. Renders on every load (BUNYIP-546): a failed fetch is
/// stated inside the card rather than hidden, because hiding it makes a broken
/// status page look like a healthy one. The list is never empty (the API always
/// returns the full set), so only the reachable / list states are drawn.
fn integrations_card(integrations: &[IntegrationStatus], fetch_error: Option<&ApiError>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Integrations" }
                p class="text-sm text-muted-foreground" { "Each optional integration and whether it is configured, off, or half-configured. Turning one on is what prompts for its credentials; a missing one degrades that capability and never stops the application." }
            }
            div class="p-6 pt-0" {
                @if let Some(e) = fetch_error {
                    (error_box_for("Could not reach the API to load integration status.", e))
                } @else {
                    div class="divide-y" { @for s in integrations { (integration_row(s)) } }
                }
            }
        }
    }
}

/// BUNYIP-931: identity of the running build. Short hash (first 12 chars) plus
/// the git-describe tag plus the UTC build date, so a hotfix patch between
/// tagged releases is distinguishable from the release itself.
fn build_card(h: &SystemHealth) -> Markup {
    let short_commit: String = h.git_commit.chars().take(12).collect();
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "API Build" }
                p class="text-sm text-muted-foreground" { "The exact source revision this instance was built from." }
            }
            div class="p-6 pt-0 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-sm" {
                div { span class="text-muted-foreground" { "Version: " } (h.version) }
                div { span class="text-muted-foreground" { "Revision: " } code class="font-mono" { (short_commit) } }
                div { span class="text-muted-foreground" { "Describe: " } code class="font-mono" { (h.git_tag) } }
                div { span class="text-muted-foreground" { "Built: " } (h.build_date) }
            }
        }
    }
}

/// BUNYIP-931: live process stats. Uptime formatted for a glance; pool numbers
/// raw so an admin can match them against the configured ceiling.
fn stats_card(h: &SystemHealth) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Stats" }
                p class="text-sm text-muted-foreground" { "What the process is doing right now." }
            }
            div class="p-6 pt-0 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-sm" {
                div { span class="text-muted-foreground" { "Uptime: " } (format_uptime(h.uptime_seconds)) }
                div { span class="text-muted-foreground" { "Database: " } (h.db_pool_idle) " idle / " (h.db_pool_size) " open" }
            }
        }
    }
}

/// Days / hours / minutes / seconds, trimmed to the largest two non-zero units;
/// a two-week uptime reads `14d 3h`, a sub-minute one `42s`.
fn format_uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Short-form summary of the API's update-check block. The payload is opaque
/// JSON here (its full shape lives in a dunite crate), so this reads the
/// bits the operator cares about ("a newer version is available: X") and
/// elides the rest. An unexpected shape renders nothing rather than guessing.
fn update_summary(update: Option<&serde_json::Value>) -> Option<String> {
    let obj = update?.as_object()?;
    let available = obj
        .get("available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !available {
        return None;
    }
    let latest = obj
        .get("latest_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if latest.is_empty() {
        Some("A newer version is available upstream.".to_string())
    } else {
        Some(format!("A newer version is available upstream: {latest}."))
    }
}

/// Version card: the API's version/revision alongside bunyip-web's own, so
/// an admin can tell what is deployed without `curl /version` by hand and
/// can also catch a half-deploy where one half of the pair fell behind.
/// A failed API fetch degrades to "Unknown" rather than breaking the card.
fn version_card(api_version: Option<&ApiVersion>, api_error: Option<&ApiError>) -> Markup {
    let short_api_revision: Option<String> = api_version
        .map(|v| v.revision.chars().take(12).collect::<String>())
        .filter(|s| !s.is_empty());
    let web_revision: String = env!("GIT_COMMIT").chars().take(12).collect();
    let web_version = env!("CARGO_PKG_VERSION");
    let web_tag = env!("GIT_TAG");
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Version" }
                p class="text-sm text-muted-foreground" { "The exact releases this instance is running: bunyip-api (the backend) and bunyip-web (this page). A mismatch after a deploy means one half of the pair fell behind." }
            }
            div class="p-6 pt-0 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4 text-sm" {
                div class="space-y-1" {
                    p class="font-medium" { "API (bunyip-api)" }
                    @match api_version {
                        Some(v) => {
                            div { span class="text-muted-foreground" { "Version: " } (if v.version.is_empty() { "Unknown" } else { v.version.as_str() }) }
                            div {
                                span class="text-muted-foreground" { "Revision: " }
                                @match short_api_revision.as_deref() {
                                    Some(r) if !r.is_empty() => code class="font-mono" { (r) },
                                    _ => span { "Unknown" },
                                }
                            }
                            @if let Some(msg) = update_summary(v.update.as_ref()) {
                                p class="mt-1 text-xs text-amber-700 dark:text-amber-400" { (msg) }
                            }
                        }
                        None => {
                            div { span class="text-muted-foreground" { "Version: " } "Unknown" }
                            div { span class="text-muted-foreground" { "Revision: " } "Unknown" }
                            @if let Some(e) = api_error {
                                p class="mt-1 text-xs text-muted-foreground" { "The API's /version endpoint did not respond: " (e.message) }
                            }
                        }
                    }
                }
                div class="space-y-1" {
                    p class="font-medium" { "Web (bunyip-web)" }
                    div { span class="text-muted-foreground" { "Version: " } (web_version) }
                    div { span class="text-muted-foreground" { "Revision: " } code class="font-mono" { (web_revision) } }
                    div { span class="text-muted-foreground" { "Describe: " } code class="font-mono" { (web_tag) } }
                }
            }
        }
    }
}

fn status_content(
    health: Option<&SystemHealth>,
    integrations: &[IntegrationStatus],
    fetch_error: Option<&ApiError>,
    health_error: Option<&ApiError>,
    api_version: Option<&ApiVersion>,
    api_version_error: Option<&ApiError>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "System Status" } p class="mt-2 text-muted-foreground" { "The running build, live process stats, and each optional integration's state." } }
            (version_card(api_version, api_version_error))
            @if let Some(h) = health {
                (build_card(h))
                (stats_card(h))
            } @else if let Some(e) = health_error {
                (error_box_for("Could not reach the API to load build + stats.", e))
            }
            (integrations_card(integrations, fetch_error))
        }
    }
}

/// GET /admin/status
pub async fn system_status(State(st): State<crate::web::AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-546: keep the reachable flag beside the fallback, so "could not
    // load" stays distinct from "everything is configured".
    // BUNYIP-931: build info + stats come from the same /admin/health endpoint
    // the dashboard's Datasets card already reads. Two reads are tolerated: the
    // page is admin-only and renders at human cadence, so one extra API call
    // beats inventing a combined endpoint only this page would use.
    // Root-level `/version` is unauthenticated, so no cookie is forwarded.
    // BUNYIP-963: none of the three fetches consumes another's result, so they
    // run concurrently via `join!`, not `try_join!`: each keeps its own
    // fallback below.
    let (fetched, fetched_health, fetched_api_version) = tokio::join!(
        admin_api::integration_status(&st.api, c.forward.as_deref()),
        admin_api::system_health(&st.api, c.forward.as_deref()),
        admin_api::api_version(&st.api)
    );
    let fetch_error = fetched.as_ref().err().cloned();
    let integrations = fetched.unwrap_or_default();
    let health_error = fetched_health.as_ref().err().cloned();
    let health = fetched_health.ok();
    let api_version_error = fetched_api_version.as_ref().err().cloned();
    let api_version = fetched_api_version.ok();
    let content = status_content(
        health.as_ref(),
        &integrations,
        fetch_error.as_ref(),
        health_error.as_ref(),
        api_version.as_ref(),
        api_version_error.as_ref(),
    );
    admin_response(&c, &user, "/admin/status", "System Status", content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::IntegrationState;

    fn load_error() -> ApiError {
        ApiError {
            status: 500,
            code: "INTERNAL_ERROR".into(),
            message: "Failed to load integration status".into(),
            retry_after: None,
            request_id: Some("req_abc123".into()),
            bucket: None,
        }
    }

    fn row(key: &str, state: IntegrationState, detail: &str, remedy: &str) -> IntegrationStatus {
        IntegrationStatus {
            key: key.to_string(),
            name: key.to_string(),
            state,
            detail: detail.to_string(),
            remedy: remedy.to_string(),
        }
    }

    #[test]
    fn each_state_renders_its_own_badge() {
        let rows = vec![
            row(
                "email",
                IntegrationState::Failing,
                "SMTP_PASSWORD unset",
                "Set it",
            ),
            row(
                "stripe",
                IntegrationState::Unconfigured,
                "Billing off",
                "Enter key",
            ),
            row("oci", IntegrationState::Configured, "Enabled", ""),
        ];
        let html = integrations_card(&rows, None).into_string();
        assert!(html.contains(">Failing<"), "failing badge");
        assert!(html.contains(">Unconfigured<"), "unconfigured badge");
        assert!(html.contains(">Configured<"), "configured badge");
        // The reason and remedy are rendered.
        assert!(html.contains("SMTP_PASSWORD unset"));
        assert!(html.contains("Enter key"));
    }

    /// A configured integration carries no remedy, so its row shows none.
    #[test]
    fn a_configured_row_shows_no_remedy() {
        let html = integrations_card(
            &[row("oci", IntegrationState::Configured, "Enabled", "")],
            None,
        )
        .into_string();
        assert!(html.contains("Enabled"));
        assert!(!html.contains("Enter key"));
    }

    /// BUNYIP-546: a failed fetch is a distinct, stated state, not an empty card
    /// that reads as "everything is fine".
    #[test]
    fn an_unreachable_api_is_stated_inside_the_card() {
        let err = load_error();
        let html = integrations_card(&[], Some(&err)).into_string();
        assert!(
            html.contains("Could not reach the API to load integration status."),
            "{html}"
        );
    }

    fn sample_health() -> SystemHealth {
        SystemHealth {
            version: "0.19.0".to_string(),
            git_commit: "deadbeefcafebabe1234".to_string(),
            git_tag: "v0.19.0".to_string(),
            build_date: "2026-10-20T12:00:00Z".to_string(),
            uptime_seconds: 3_600 * 25,
            db_pool_size: 10,
            db_pool_idle: 7,
            datasets: Vec::new(),
        }
    }

    /// BUNYIP-931: Build card renders the three identity fields; the commit is
    /// truncated to its first 12 chars so a 40-char SHA does not wrap.
    #[test]
    fn build_card_renders_version_short_commit_tag_and_date() {
        let html = build_card(&sample_health()).into_string();
        assert!(html.contains("0.19.0"), "{html}");
        assert!(html.contains("deadbeefcafe"), "short commit: {html}");
        assert!(
            !html.contains("deadbeefcafebabe1234"),
            "full commit must be truncated: {html}"
        );
        assert!(html.contains("v0.19.0"), "describe: {html}");
        assert!(html.contains("2026-10-20T12:00:00Z"), "build date: {html}");
    }

    /// BUNYIP-931: Stats card shows the formatted uptime plus idle / open
    /// counts; the raw numbers match what an operator sees in `psql`.
    #[test]
    fn stats_card_renders_uptime_and_pool_counts() {
        let html = stats_card(&sample_health()).into_string();
        assert!(
            html.contains("1d 1h"),
            "25h uptime formats as 1d 1h: {html}"
        );
        assert!(html.contains("7"), "idle count: {html}");
        assert!(html.contains("10"), "pool size: {html}");
    }

    /// Uptime formatter trims to the two largest non-zero units.
    #[test]
    fn uptime_formats_each_scale() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(42), "42s");
        assert_eq!(format_uptime(65), "1m 5s");
        assert_eq!(format_uptime(3_725), "1h 2m");
        assert_eq!(format_uptime(86_400 + 7_200), "1d 2h");
    }

    fn sample_api_version() -> ApiVersion {
        ApiVersion {
            version: "v0.19.0".into(),
            revision: "deadbeefcafebabe1234567890abcdef12345678".into(),
            update: None,
        }
    }

    /// Version card prints the API's version and a short revision
    /// alongside the web's own build info, so an admin reads what each
    /// half of the deployment is actually running without `curl`.
    #[test]
    fn version_card_shows_api_and_web_sides() {
        let html = version_card(Some(&sample_api_version()), None).into_string();
        assert!(html.contains("API (bunyip-api)"), "API label: {html}");
        assert!(html.contains("v0.19.0"), "API version string: {html}");
        assert!(html.contains("deadbeefcafe"), "API short revision: {html}");
        assert!(
            !html.contains("deadbeefcafebabe1234567890"),
            "full API commit must be truncated: {html}"
        );
        assert!(
            html.contains("Web (bunyip-web)"),
            "web label is distinct: {html}"
        );
    }

    /// A failed `/version` fetch degrades the card to "Unknown" without
    /// breaking the page, since the integrations and health cards below
    /// still carry useful information even when `/version` is unreachable.
    #[test]
    fn version_card_degrades_to_unknown_on_fetch_error() {
        let html = version_card(None, Some(&load_error())).into_string();
        assert!(
            html.contains("Unknown"),
            "version/revision read Unknown on error: {html}"
        );
        assert!(
            html.contains("Failed to load integration status"),
            "the error message is surfaced for the operator: {html}"
        );
    }

    /// `update.available = true` with a `latest_version` renders the amber
    /// hint operators look for; `available = false` renders nothing so a
    /// current build does not shout.
    #[test]
    fn update_summary_only_shows_when_an_upgrade_is_available() {
        let none = update_summary(Some(
            &serde_json::json!({ "available": false, "latest_version": "v9.9.9" }),
        ));
        assert!(none.is_none(), "nothing to surface when not available");
        let msg = update_summary(Some(
            &serde_json::json!({ "available": true, "latest_version": "v0.20.0" }),
        ))
        .expect("available=true should surface");
        assert!(
            msg.contains("v0.20.0"),
            "the latest version is named: {msg}"
        );
    }
}
