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
use crate::views::ui::{button_class, error_box, icon};
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
    /// BUNYIP-406: the requesting client's icon/logo URL, passed by the
    /// authorize handler alongside `client_name`. Absent when the client has no
    /// logo (or on an older backend); the card then shows a name-initial badge.
    #[serde(default)]
    pub logo_uri: Option<String>,
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
///
/// BUNYIP-561: the account being accessed is named from the admin-managed brand
/// record. An unbranded deployment says "your account" rather than carrying a
/// product name compiled into the binary.
fn consent_description(client_name: Option<&str>, brand_name: &str) -> String {
    let account = if brand_name.is_empty() {
        "your account".to_string()
    } else {
        format!("your {brand_name} account")
    };
    match client_name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) => {
            format!("{name} is requesting access to {account}. Approve below to continue.")
        }
        None => {
            format!("An application is requesting access to {account}. Approve below to continue.")
        }
    }
}

/// BUNYIP-406: only an `https://` or same-origin (`/…`) logo URL is rendered as
/// an `<img>`; any other scheme (`javascript:`, `data:`, plaintext `http:` on
/// an https page) degrades to the initial badge. Maud already escapes the
/// attribute so a spoofed value cannot inject markup - this additionally keeps a
/// hostile or unloadable URL from being requested at all, and matches the page
/// CSP (`img-src 'self' https:`).
fn safe_logo_uri(logo_uri: Option<&str>) -> Option<&str> {
    let u = logo_uri.map(str::trim).filter(|s| !s.is_empty())?;
    (u.starts_with("https://") || u.starts_with('/')).then_some(u)
}

/// The app-identity row on the consent card: the client's logo when a safe URL
/// is set, otherwise a name-initial badge (generic app glyph when the name is
/// also absent), next to the client name. Rendered by Maud as escaped text /
/// attributes, so a spoofed name or logo URL cannot inject markup.
fn app_identity(client_name: Option<&str>, logo_uri: Option<&str>) -> Markup {
    let name = client_name.map(str::trim).filter(|n| !n.is_empty());
    let initial = name
        .and_then(|n| n.chars().next())
        .map(|c| c.to_ascii_uppercase().to_string());
    html! {
        div class="mb-4 flex items-center gap-3 rounded-lg border border-border/60 p-3" {
            @if let Some(logo) = safe_logo_uri(logo_uri) {
                img src=(logo) alt="" class="h-10 w-10 shrink-0 rounded-lg object-cover border border-border/60";
            } @else if let Some(i) = &initial {
                span class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-indigo-500 text-white text-lg font-semibold" aria-hidden="true" { (i) }
            } @else {
                span class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground" aria-hidden="true" { (icon("app-window", "h-5 w-5")) }
            }
            span class="font-medium truncate" { (name.unwrap_or("An application")) }
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
        // BUNYIP-406: name + icon of the requesting application.
        (app_identity(q.client_name.as_deref(), q.logo_uri.as_deref()))
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
        "bg-primary/10 text-primary-text",
        "Approve access",
        &consent_description(
            q.client_name.as_deref(),
            &crate::views::layout::brand_name(),
        ),
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
    auth_page(&st, &headers, "Approve access", card).await
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
    use super::{app_identity, consent_description, safe_logo_uri, scope_label};

    #[test]
    fn consent_description_names_the_client_or_falls_back() {
        assert!(
            consent_description(Some("Mokosh"), "Acme").starts_with("Mokosh is requesting access")
        );
        assert!(
            consent_description(None, "Acme").starts_with("An application is requesting access")
        );
        // A blank / whitespace-only name falls back to the generic wording.
        assert!(
            consent_description(Some("   "), "Acme").starts_with("An application is requesting")
        );
    }

    /// BUNYIP-406: the copy names the account being accessed, both when the
    /// client is named and in the generic fallback. BUNYIP-561: that name is
    /// the admin-managed brand, and an unbranded deployment says "your account"
    /// rather than falling back to a compiled-in product name.
    #[test]
    fn consent_copy_names_the_branded_account() {
        assert!(consent_description(Some("Mokosh"), "Acme").contains("your Acme account"));
        assert!(consent_description(None, "Acme").contains("your Acme account"));
        assert!(consent_description(Some("Mokosh"), "").contains("access to your account"));
        assert!(consent_description(None, "").contains("access to your account"));
    }

    /// BUNYIP-406: only https / same-origin logo URLs are honoured; every other
    /// scheme degrades to the initial badge (and never gets requested).
    #[test]
    fn safe_logo_uri_allows_https_and_self_only() {
        assert_eq!(
            safe_logo_uri(Some("https://cdn.example.com/logo.png")),
            Some("https://cdn.example.com/logo.png")
        );
        assert_eq!(
            safe_logo_uri(Some("/assets/mokosh.svg")),
            Some("/assets/mokosh.svg")
        );
        assert_eq!(safe_logo_uri(Some("javascript:alert(1)")), None);
        assert_eq!(
            safe_logo_uri(Some("data:image/svg+xml,<svg onload=alert(1)>")),
            None
        );
        assert_eq!(
            safe_logo_uri(Some("http://insecure.example.com/logo.png")),
            None
        );
        assert_eq!(safe_logo_uri(Some("   ")), None);
        assert_eq!(safe_logo_uri(None), None);
    }

    /// BUNYIP-406: a spoofed client name or logo URL cannot inject markup, and a
    /// hostile logo scheme is not emitted as an `<img src>` at all.
    #[test]
    fn app_identity_escapes_spoofed_name_and_rejects_hostile_logo() {
        let html = app_identity(Some("<script>alert(1)</script>Evil"), None).into_string();
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw markup must not appear"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "name is rendered as escaped text"
        );

        // A javascript: logo degrades to the initial badge - no <img>, no URL.
        let hostile = app_identity(Some("Evil"), Some("javascript:alert(1)")).into_string();
        assert!(!hostile.contains("javascript:"));
        assert!(!hostile.contains("<img"));

        // A safe https logo IS rendered as an (escaped) <img src>.
        let ok = app_identity(Some("Mokosh"), Some("https://cdn.example.com/m.png")).into_string();
        assert!(ok.contains(r#"<img src="https://cdn.example.com/m.png""#));
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
