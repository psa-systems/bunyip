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
use crate::api::types::{IntegrationState, IntegrationStatus};
use crate::handlers::{admin_guard, admin_response};
use crate::views::ui::{badge, error_box};

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
fn integrations_card(integrations: &[IntegrationStatus], reachable: bool) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Integrations" }
                p class="text-sm text-muted-foreground" { "Each optional integration and whether it is configured, off, or half-configured. Turning one on is what prompts for its credentials; a missing one degrades that capability and never stops the application." }
            }
            div class="p-6 pt-0" {
                @if !reachable {
                    (error_box("Could not reach the API to load integration status."))
                } @else {
                    div class="divide-y" { @for s in integrations { (integration_row(s)) } }
                }
            }
        }
    }
}

fn status_content(integrations: &[IntegrationStatus], reachable: bool) -> Markup {
    html! {
        div class="space-y-6" {
            (integrations_card(integrations, reachable))
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
    let fetched = admin_api::integration_status(&st.api, c.forward.as_deref()).await;
    let reachable = fetched.is_ok();
    let integrations = fetched.unwrap_or_default();
    let content = status_content(&integrations, reachable);
    admin_response(&c, &user, "/admin/status", "System Status", content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::IntegrationState;

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
        let html = integrations_card(&rows, true).into_string();
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
            true,
        )
        .into_string();
        assert!(html.contains("Enabled"));
        assert!(!html.contains("Enter key"));
    }

    /// BUNYIP-546: a failed fetch is a distinct, stated state, not an empty card
    /// that reads as "everything is fine".
    #[test]
    fn an_unreachable_api_is_stated_inside_the_card() {
        let html = integrations_card(&[], false).into_string();
        assert!(
            html.contains("Could not reach the API to load integration status."),
            "{html}"
        );
    }
}
