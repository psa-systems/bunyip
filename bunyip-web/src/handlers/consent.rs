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
    /// Human-readable name of the requesting client (BUNYIP-342), passed by the
    /// authorize handler so the screen can name the app. Absent on a
    /// hand-crafted URL or an older backend.
    #[serde(default)]
    pub client_name: Option<String>,
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

/// The consent card's lead sentence. Names the requesting application when the
/// authorize handler passed a client name (BUNYIP-342); falls back to the
/// generic wording for a hand-crafted URL or an older backend that sends none.
/// Rendered as escaped text by Maud, so a spoofed name cannot inject markup.
fn consent_description(client_name: Option<&str>) -> String {
    match client_name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) => {
            format!("{name} is requesting access to your information. Approve below to continue.")
        }
        None => {
            "An application is requesting access to your information. Approve below to continue."
                .to_string()
        }
    }
}

/// Whether a consent `continue_url` is safe to 302 back to: it must be an
/// absolute URL under the OP issuer origin (the `/oauth2/authorize` round-trip),
/// not an attacker-supplied absolute URL. The trailing-slash boundary stops a
/// look-alike host (`https://issuer.evil.com/...`) from passing the prefix
/// check. Closes an open redirect on both the Allow and Deny paths (BUNYIP-342).
fn continue_under_issuer(continue_url: &str, oidc_issuer: &str) -> bool {
    let u = continue_url.trim();
    let origin = oidc_issuer.trim_end_matches('/');
    !origin.is_empty() && (u == origin || u.starts_with(&format!("{origin}/")))
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
        &consent_description(q.client_name.as_deref()),
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
        // BUNYIP-342 Deny: bounce back through the authorize handler with
        // consent=denied. bunyip-api validated redirect_uri on its side, so it
        // returns the spec `access_denied` error to the RP (RFC 6749 4.1.2.1)
        // instead of leaving the RP hanging. Only follow a continue_url under
        // the OP issuer origin - an attacker-supplied absolute continue_url is
        // refused to the dashboard, closing an open redirect. We never redirect
        // to a redirect_uri ourselves; the validated authorize round-trip does.
        let dest = if !continue_under_issuer(&f.continue_url, &st.cfg.oidc_issuer) {
            "/dashboard?error=Authorization+declined.".to_string()
        } else if f.continue_url.contains('?') {
            format!("{}&consent=denied", f.continue_url)
        } else {
            format!("{}?consent=denied", f.continue_url)
        };
        return redirect_cookies(&dest, &c.set_cookies);
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
    // Only resume to a continue_url under the OP issuer origin; an
    // attacker-supplied absolute URL is refused to the dashboard (BUNYIP-342
    // open-redirect fix, same guard as the Deny path).
    let dest = if continue_under_issuer(&f.continue_url, &st.cfg.oidc_issuer) {
        f.continue_url.clone()
    } else {
        "/dashboard".to_string()
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

#[cfg(test)]
mod tests {
    use super::{consent_description, scope_label};

    #[test]
    fn consent_description_names_the_client_or_falls_back() {
        assert!(consent_description(Some("Mokosh")).starts_with("Mokosh is requesting access"));
        assert!(consent_description(None).starts_with("An application is requesting access"));
        // A blank / whitespace-only name falls back to the generic wording.
        assert!(consent_description(Some("   ")).starts_with("An application is requesting access"));
    }

    #[test]
    fn scope_label_covers_known_and_unknown_scopes() {
        assert_eq!(scope_label("profile"), "Your first and last name");
        assert_eq!(scope_label("phone"), "Your phone number");
        assert_eq!(scope_label("something_new"), "Additional account details");
    }

    #[test]
    fn continue_under_issuer_requires_origin_boundary() {
        let iss = "https://api.psa.systems";
        assert!(super::continue_under_issuer(
            "https://api.psa.systems/oauth2/authorize?client_id=x",
            iss
        ));
        assert!(super::continue_under_issuer(
            "https://api.psa.systems/",
            iss
        ));
        // Look-alike host must not pass the prefix check (open-redirect guard).
        assert!(!super::continue_under_issuer(
            "https://api.psa.systems.evil.com/x",
            iss
        ));
        assert!(!super::continue_under_issuer("https://evil.com", iss));
        assert!(!super::continue_under_issuer("", iss));
        // A relative path is not under the absolute issuer origin.
        assert!(!super::continue_under_issuer("/dashboard", iss));
        // Trailing slash on the configured issuer is tolerated.
        assert!(super::continue_under_issuer(
            "https://api.psa.systems/oauth2/authorize?a=1",
            "https://api.psa.systems/"
        ));
    }
}
