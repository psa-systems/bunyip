//! Request-scoped authentication for the BFF.
//!
//! `authenticate` validates the forwarded session cookie against `/users/me`.
//! On a 401 it tries `/auth/refresh` once and, if that rotates the cookie,
//! re-reads `/users/me` with the merged cookie. The rotated `Set-Cookie`s are
//! returned for relay to the browser, and `forward` is the cookie string to use
//! for any further API calls in the same request (so they see the fresh token).
//!
//! BUNYIP-308: after `/users/me` returns 200, compare the DB role reported
//! there with the `role` claim decoded (unverified) from the cookie's at+jwt.
//! If they differ (freshly promoted or demoted user, tokens minted before the
//! `AdminUser` extractor gate flipped), force a refresh so the rotated at+jwt
//! carries the current DB role. Without this the browser could hold a
//! subscriber-role at+jwt for up to 15 minutes after a promotion and every
//! `/v1/admin/*` fetch on the admin shell would 403.

use std::collections::BTreeMap;

use axum::http::{header::COOKIE, HeaderMap};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::api::{
    self,
    types::{User, UserRole},
    Api,
};

/// Read the `Cookie` request header.
pub fn req_cookie(headers: &HeaderMap) -> Option<String> {
    headers.get(COOKIE)?.to_str().ok().map(str::to_string)
}

pub struct AuthCtx {
    pub user: Option<User>,
    /// `Set-Cookie` strings to relay back to the browser (from a refresh).
    pub set_cookies: Vec<String>,
    /// Cookie header to forward on further API calls this request.
    pub forward: Option<String>,
}

impl AuthCtx {
    pub fn is_signed_in(&self) -> bool {
        self.user.is_some()
    }
}

pub async fn authenticate(api: &Api, cookie: Option<&str>) -> AuthCtx {
    let Some(cookie) = cookie else {
        return AuthCtx {
            user: None,
            set_cookies: vec![],
            forward: None,
        };
    };

    match api::auth::me(api, Some(cookie)).await {
        Ok(user) => {
            // BUNYIP-308: /users/me returned a fresh DB view. If the DB role
            // no longer matches the cookie's at+jwt role claim, the user was
            // just promoted / demoted and their in-flight token is stale.
            // Force one refresh so the rotated at+jwt carries the current
            // role, and the downstream /v1/admin/* fetches in the same
            // request see it. On refresh failure fall back to the pre-refresh
            // path - bunyip-api will 401/403 on the mismatched claim and the
            // next click / reload lands the user at /login.
            if let Some(jwt_role) = access_token_role_claim(cookie) {
                if !role_matches(&user.role, &jwt_role) {
                    if let Ok(set) = api::auth::refresh(api, Some(cookie)).await {
                        let merged = merge_cookies(Some(cookie), &set);
                        // Re-read /users/me with the fresh cookie so the returned
                        // User struct is guaranteed consistent with the rotated
                        // token (bunyip-api's refresh path re-fetches the user
                        // from the DB before minting, so the two agree by
                        // construction; the extra call is defensive against a
                        // parallel DB write racing our compare).
                        let user_after = api::auth::me(api, Some(&merged)).await.unwrap_or(user);
                        return AuthCtx {
                            user: Some(user_after),
                            set_cookies: set,
                            forward: Some(merged),
                        };
                    }
                }
            }
            AuthCtx {
                user: Some(user),
                set_cookies: vec![],
                forward: Some(cookie.to_string()),
            }
        }
        Err(e) if e.status == 401 => match api::auth::refresh(api, Some(cookie)).await {
            Ok(set) => {
                let merged = merge_cookies(Some(cookie), &set);
                let user = api::auth::me(api, Some(&merged)).await.ok();
                AuthCtx {
                    user,
                    set_cookies: set,
                    forward: Some(merged),
                }
            }
            Err(_) => AuthCtx {
                user: None,
                set_cookies: vec![],
                forward: Some(cookie.to_string()),
            },
        },
        Err(_) => AuthCtx {
            user: None,
            set_cookies: vec![],
            forward: Some(cookie.to_string()),
        },
    }
}

/// BUNYIP-308: unverified decode of the `role` claim from an `access_token`
/// cookie's JWT payload. Returns `None` when the cookie has no `access_token`
/// entry, the token is not a well-formed three-segment JWT, the middle
/// segment does not base64url-decode, or the JSON does not carry a string
/// `role` field.
///
/// Signature verification is deliberately not done here. bunyip-api's
/// `/users/me` call that ran BEFORE this decode already validated the token
/// against its keys; we only decode the payload to compare `role` for the
/// stale-token detection. A `None` return simply skips the mismatch check
/// and preserves the pre-BUNYIP-308 behaviour, so a malformed cookie is safe
/// (bunyip-api will still reject it on the next call if invalid).
fn access_token_role_claim(cookie_header: &str) -> Option<String> {
    let token = cookie_value_from_header(cookie_header, "access_token")?;
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    value.get("role")?.as_str().map(str::to_string)
}

fn cookie_value_from_header(header: &str, name: &str) -> Option<String> {
    for kv in header.split(';') {
        if let Some((n, v)) = kv.split_once('=') {
            if n.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Compare a `UserRole` (from the /users/me DB view) with the raw string
/// pulled from the JWT `role` claim (bunyip-api mints the claim as
/// `subscriber`, `admin`, ...). Returns true when they represent the same
/// role, false otherwise (including for an unknown JWT string, so the
/// mismatch path treats "we cannot make sense of this claim" as "rotate").
fn role_matches(user_role: &UserRole, jwt_role: &str) -> bool {
    // BUNYIP-506: a role this build does not recognise matches nothing, so the
    // caller treats it as a mismatch and rotates rather than trusting it.
    if matches!(user_role, UserRole::Unknown) {
        return false;
    }
    user_role.as_str() == jwt_role
}

fn cookie_name_value(set_cookie: &str) -> Option<(String, String)> {
    let first = set_cookie.split(';').next()?;
    let (n, v) = first.split_once('=')?;
    Some((n.trim().to_string(), v.trim().to_string()))
}

/// Merge the original `Cookie` header with `Set-Cookie` values (later wins;
/// empty value = deletion).
pub fn merge_cookies(original: Option<&str>, set_cookies: &[String]) -> String {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    if let Some(orig) = original {
        for kv in orig.split(';') {
            if let Some((n, v)) = kv.split_once('=') {
                map.insert(n.trim().to_string(), v.trim().to_string());
            }
        }
    }
    for sc in set_cookies {
        if let Some((n, v)) = cookie_name_value(sc) {
            if v.is_empty() {
                map.remove(&n);
            } else {
                map.insert(n, v);
            }
        }
    }
    map.iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fake three-segment JWT whose payload carries the given role.
    /// Signature is a fixed placeholder - `access_token_role_claim` never
    /// verifies it.
    fn jwt_with_role(role: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"sub": "00000000-0000-0000-0000-000000000001", "role": role})
                .to_string()
                .as_bytes(),
        );
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn decodes_admin_role_from_access_token_cookie() {
        let token = jwt_with_role("admin");
        let cookie = format!("other=x; access_token={token}; refresh_token=y");
        assert_eq!(access_token_role_claim(&cookie).as_deref(), Some("admin"));
    }

    #[test]
    fn decodes_subscriber_role_from_access_token_cookie() {
        let token = jwt_with_role("subscriber");
        let cookie = format!("access_token={token}");
        assert_eq!(
            access_token_role_claim(&cookie).as_deref(),
            Some("subscriber")
        );
    }

    #[test]
    fn returns_none_when_access_token_missing() {
        let cookie = "refresh_token=x; some_other=y";
        assert!(access_token_role_claim(cookie).is_none());
    }

    #[test]
    fn returns_none_for_malformed_token() {
        // Not three segments.
        let cookie = "access_token=not.a.valid.jwt";
        // `not.a.valid.jwt` splits into four parts; `nth(1)` returns `"a"`,
        // which does not base64url-decode to JSON.
        assert!(access_token_role_claim(cookie).is_none());
    }

    #[test]
    fn returns_none_when_payload_has_no_role_field() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        let token = format!("{header}.{payload}.sig");
        let cookie = format!("access_token={token}");
        assert!(access_token_role_claim(&cookie).is_none());
    }

    #[test]
    fn role_matches_agrees_on_admin_pair() {
        assert!(role_matches(&UserRole::Admin, "admin"));
    }

    #[test]
    fn role_matches_agrees_on_subscriber_pair() {
        assert!(role_matches(&UserRole::Subscriber, "subscriber"));
    }

    #[test]
    fn role_matches_flags_promotion_mismatch() {
        // The scenario BUNYIP-308 exists to catch: DB says admin, JWT says
        // subscriber -> mismatch -> authenticate rotates.
        assert!(!role_matches(&UserRole::Admin, "subscriber"));
    }

    #[test]
    fn role_matches_flags_demotion_mismatch() {
        // Reverse direction: DB says subscriber, JWT still says admin ->
        // mismatch -> rotate (and bunyip-api will likely 401 on refresh if
        // the session was revoked, taking the user to /login).
        assert!(!role_matches(&UserRole::Subscriber, "admin"));
    }

    #[test]
    fn role_matches_flags_unknown_jwt_role() {
        // Defensive: an unrecognized JWT string is treated as a mismatch so
        // the rotation path fires and gets us to a known-good token.
        assert!(!role_matches(&UserRole::Admin, ""));
        assert!(!role_matches(&UserRole::Admin, "root"));
    }
}
