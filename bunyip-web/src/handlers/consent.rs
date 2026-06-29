//! BUNYIP-140: OIDC consent screen.
//!
//! The `/oauth2/authorize` handler in bunyip-api redirects here when a
//! relying party's requested scope set contains any scope the user has not
//! yet consented to. We render an "Allow / Deny" card listing the requested
//! scopes and the concrete fields each one discloses; Allow POSTs the new
//! grant to bunyip-api and resumes the original authorize flow; Deny drops
//! the user back to the dashboard with a flash.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::handlers::{auth_page, guard};
use crate::views::common::auth_card;
use crate::views::ui::{button_class, error_box};
use crate::web::{redirect, redirect_cookies, AppState};

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub client_id: String,
    /// Space-separated scope strings.
    pub missing: String,
    /// Absolute URL the authorize handler wants us to send the user back to
    /// after Allow. Already URL-encoded by the caller.
    #[serde(default, rename = "continue")]
    pub continue_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub client_id: String,
    pub scopes: String,
    pub continue_url: String,
    /// "allow" or "deny". Anything else is treated as deny.
    pub action: String,
}

/// Render a one-line summary of the concrete fields a scope discloses, in
/// plain English. Reads from a fixed table so new scopes added later get a
/// matching entry rather than a confusing fallback.
fn scope_label(scope: &str) -> &'static str {
    match scope {
        "profile" => "Your first and last name",
        "phone" => "Your phone number",
        // openid / email / offline_access are baseline-granted and should
        // not reach this screen, but a future RP requesting a non-baseline
        // scope without an entry here gets a safe-but-vague fallback.
        _ => "Additional account details",
    }
}

/// GET /oauth2/consent
pub async fn consent_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ConsentQuery>,
) -> Response {
    let (_user, c) = match guard(&st, &headers, "/oauth2/consent").await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let scopes: Vec<&str> = q.missing.split_whitespace().collect();
    if scopes.is_empty() {
        // Nothing to consent to - shouldn't happen because the authorize
        // handler only redirects here when `missing` is non-empty, but a
        // hand-crafted URL could reach this branch. Fall back to a generic
        // error rather than rendering an empty card.
        return redirect("/dashboard");
    }

    let body = html! {
        ul class="mb-4 space-y-2 list-disc list-inside text-sm" {
            @for s in &scopes {
                li { (scope_label(s)) }
            }
        }
        form method="post" action="/oauth2/consent" class="space-y-3" {
            input type="hidden" name="client_id" value=(q.client_id);
            input type="hidden" name="scopes" value=(q.missing);
            input type="hidden" name="continue_url" value=(q.continue_url);
            button type="submit" name="action" value="allow"
                class=(button_class("default", "default", "w-full")) { "Allow" }
            button type="submit" name="action" value="deny"
                class=(button_class("outline", "default", "w-full")) { "Deny" }
        }
    };

    let card = auth_card(
        "shield",
        "bg-primary/10 text-primary",
        "Approve access",
        "An application is requesting access to your information. Approve below to continue.",
        body,
    );

    // BUNYIP-223: render through `auth_page` so the public shell wraps the
    // card with `<head>` + stylesheet link + brand chrome - matching every
    // other auth-flow page (`/login`, `/register`, `/magic-link`, etc.).
    // The prior `render_html(card)` shipped bare Markup with no CSS so the
    // shield SVG rendered at the browser's default ~500px size and the
    // Tailwind classes had no effect (giant icon, unstyled bullets, naked
    // buttons in the corner). `auth_page` owns its own cookie / context
    // round-trip so the `c` we got from `guard` is intentionally dropped.
    let _ = c;
    auth_page(&st, &headers, "Approve access · Bunyip", card).await
}

/// POST /oauth2/consent
pub async fn consent_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ConsentForm>,
) -> Response {
    let (_user, c) = match guard(&st, &headers, "/oauth2/consent").await {
        Ok(v) => v,
        Err(r) => return r,
    };

    if f.action != "allow" {
        // Deny path: drop back to dashboard with a flash. A future iteration
        // can parse `continue_url` for the RP's redirect_uri + state and
        // 302 there with error=access_denied per the OIDC spec, but for
        // first-cut UX this is fine.
        return redirect_cookies("/dashboard?error=Authorization+declined.", &c.set_cookies);
    }

    // bunyip-api parses + validates the client_id UUID on its side; pass
    // the raw string through so bunyip-web does not need uuid as a dep.
    if f.client_id.is_empty() {
        return redirect_cookies("/dashboard?error=Invalid+client+id.", &c.set_cookies);
    }
    let scopes: Vec<String> = f.scopes.split_whitespace().map(str::to_string).collect();

    let body = json!({ "client_id": f.client_id, "scopes": scopes });
    let r = match st
        .api
        .post("/users/me/consents", c.forward.as_deref(), Some(body))
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return redirect_cookies("/dashboard?error=Could+not+save+consent.", &c.set_cookies);
        }
    };
    if !r.ok() {
        return redirect_cookies("/dashboard?error=Could+not+save+consent.", &c.set_cookies);
    }

    // Resume the original authorize round-trip. `continue_url` is the full
    // absolute URL the authorize handler bounced us off of; redirecting back
    // there lets it re-evaluate the granted scope set (now widened by our
    // POST) and mint the auth code.
    let dest = if f.continue_url.is_empty() {
        "/dashboard".to_string()
    } else {
        f.continue_url.clone()
    };
    // BUNYIP-234: log the redirect target + scopes so the consent-loop
    // investigation can confirm the user is actually being sent back to
    // /oauth2/authorize (and not, e.g., a stale or malformed continue_url
    // that loops within bunyip-web). Pair with `consent_grant` and
    // `consent_gate` traces on bunyip-api to follow the request chain.
    tracing::info!(
        target: "consent_post",
        client_id = %f.client_id,
        scopes = ?f.scopes,
        continue_url = %dest,
        "BUNYIP-234: consent saved, redirecting to authorize"
    );
    redirect_cookies(&dest, &c.set_cookies)
}

// Keep the warning quiet for unused imports if the error_box helper ever
// drops out of this file's body during a refactor.
#[allow(dead_code)]
fn _keep_error_box_import(msg: &str) -> Markup {
    error_box(msg)
}
