//! Typed auth/account calls. Endpoints that establish or clear a session return
//! the captured `Set-Cookie` strings (`Vec<String>`) so the handler can relay
//! them to the browser.

use serde_json::{json, Value};

use super::types::{
    AuthResponse, PaginatedResponse, RecoveryCodesResponse, SetupStatus, TrustedDeviceInfo,
    TwoFactorSetupResponse, TwoFactorStatusResponse, User,
};
use super::{ok_data, parse, Api, ApiError};

/// A page of the signed-in user's trusted devices (BUNYIP-138 / BUNYIP-177).
/// The API returns a `PaginatedResponse<TrustedDeviceInfo>` inside the envelope.
pub async fn list_trusted_devices(
    api: &Api,
    cookie: Option<&str>,
    page: i64,
    per_page: i64,
) -> Result<PaginatedResponse<TrustedDeviceInfo>, ApiError> {
    parse(
        api.get(
            &format!("/users/me/trusted-devices?page={page}&per_page={per_page}"),
            cookie,
        )
        .await?,
    )
}

/// Revoke a single trusted device by id.
pub async fn revoke_trusted_device(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<(), ApiError> {
    let path = format!(
        "/users/me/trusted-devices/{}/revoke",
        urlencoding::encode(id)
    );
    let r = api.post(&path, cookie, None).await?;
    ok_data(&r).map(|_| ())
}

// BUNYIP-139: User grew three Option<String> fields, pushing the size diff
// between the two variants over clippy's default threshold. The enum is
// constructed once per login attempt - boxing would change every call site
// for a non-issue. Allow the lint locally.
#[allow(clippy::large_enum_variant)]
pub enum LoginOutcome {
    SignedIn(User),
    TwoFactorRequired { challenge_token: String },
}

fn parse_login(value: Value) -> Result<LoginOutcome, ApiError> {
    if value
        .get("requires_2fa")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let challenge_token = value
            .get("challenge_token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        return Ok(LoginOutcome::TwoFactorRequired { challenge_token });
    }
    let auth: AuthResponse = serde_json::from_value(value).map_err(|e| ApiError {
        status: 0,
        code: "DECODE_ERROR".into(),
        message: e.to_string(),
        retry_after: None,
    })?;
    Ok(LoginOutcome::SignedIn(auth.user))
}

// --- session / boot ---------------------------------------------------------

pub async fn setup_status(api: &Api) -> Result<SetupStatus, ApiError> {
    parse(api.get("/auth/setup/status", None).await?)
}

pub async fn me(api: &Api, cookie: Option<&str>) -> Result<User, ApiError> {
    parse(api.get("/users/me", cookie).await?)
}

/// Returns the rotated `Set-Cookie`s on success.
pub async fn refresh(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    let r = api.post("/auth/refresh", cookie, None).await?;
    if r.ok() {
        Ok(r.set_cookies)
    } else {
        Err(super::error_from(&r))
    }
}

pub async fn logout(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    let r = api.post("/auth/logout", cookie, None).await?;
    Ok(r.set_cookies)
}

// --- login / passwordless ---------------------------------------------------

pub async fn login(
    api: &Api,
    cookie: Option<&str>,
    email: &str,
    password: &str,
    remember: bool,
) -> Result<(LoginOutcome, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/login",
            cookie,
            Some(json!({ "email": email, "password": password, "remember": remember })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?.clone();
    Ok((parse_login(data)?, cookies))
}

pub async fn verify_2fa(
    api: &Api,
    cookie: Option<&str>,
    challenge_token: &str,
    code: &str,
) -> Result<(User, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/2fa/verify",
            cookie,
            Some(json!({
                "challenge_token": challenge_token,
                "code": code,
            })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?.clone();
    let auth: AuthResponse = serde_json::from_value(data).map_err(|e| ApiError {
        status: 0,
        code: "DECODE_ERROR".into(),
        message: e.to_string(),
        retry_after: None,
    })?;
    Ok((auth.user, cookies))
}

pub async fn request_magic_link(api: &Api, email: &str) -> Result<(), ApiError> {
    let r = api
        .post("/auth/magic-link", None, Some(json!({ "email": email })))
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn verify_magic_link(
    api: &Api,
    token: &str,
) -> Result<(LoginOutcome, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/magic-link/verify",
            None,
            Some(json!({ "token": token })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?.clone();
    Ok((parse_login(data)?, cookies))
}

pub async fn request_password_reset(api: &Api, email: &str) -> Result<(), ApiError> {
    let r = api
        .post(
            "/auth/password-reset",
            None,
            Some(json!({ "email": email })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn confirm_password_reset(
    api: &Api,
    token: &str,
    new_password: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            "/auth/password-reset/confirm",
            None,
            Some(json!({ "token": token, "new_password": new_password })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- registration / setup / invite -----------------------------------------

pub async fn register(
    api: &Api,
    email: &str,
    password: &str,
    honeypot: &str,
    signup_token: &str,
) -> Result<(User, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/register",
            None,
            // BUNYIP-377: forward the honeypot + signup timing token so bunyip-api
            // can run its bot guard (when SIGNUP_BOT_GUARD_ENABLED is on).
            Some(json!({
                "email": email,
                "password": password,
                "contact_channel": honeypot,
                "signup_token": signup_token,
            })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let auth: AuthResponse = parse(r)?;
    Ok((auth.user, cookies))
}

/// BUNYIP-377: fetch a signup timing-challenge token to embed in the register
/// form. Best-effort - on any failure returns `None` and the form embeds an
/// empty token (harmless while the bot guard is off; when on, the user just
/// reloads for a fresh one).
pub async fn register_challenge(api: &Api) -> Option<String> {
    let r = api.get("/auth/register-challenge", None).await.ok()?;
    ok_data(&r)
        .ok()?
        .get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
}

/// Returns `(maybe needs-password email, user, cookies)`. `Ok((Some(email), None, _))`
/// means the invite needs a password; `Ok((None, Some(user), cookies))` is a full sign-in.
pub async fn accept_invite(
    api: &Api,
    token: &str,
    password: Option<&str>,
) -> Result<(Option<String>, Option<User>, Vec<String>), ApiError> {
    let body = match password {
        Some(p) => json!({ "token": token, "password": p }),
        None => json!({ "token": token }),
    };
    let r = api.post("/auth/invite/accept", None, Some(body)).await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?.clone();
    if data
        .get("needs_password")
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
    {
        let email = data
            .get("email")
            .and_then(|e| e.as_str())
            .unwrap_or_default()
            .to_string();
        return Ok((Some(email), None, cookies));
    }
    let auth: AuthResponse = serde_json::from_value(data).map_err(|e| ApiError {
        status: 0,
        code: "DECODE_ERROR".into(),
        message: e.to_string(),
        retry_after: None,
    })?;
    Ok((None, Some(auth.user), cookies))
}

// --- account / email / password --------------------------------------------

/// BUNYIP-139: persist optional first_name / last_name / phone via
/// `PUT /v1/users/me/profile`. Each arg follows the API contract:
/// - `Some("trimmed value")` -> write the value
/// - `Some("")` -> clear the column to NULL
/// - `None` -> leave the column unchanged (key absent in the JSON body)
pub async fn update_profile(
    api: &Api,
    cookie: Option<&str>,
    first_name: Option<&str>,
    last_name: Option<&str>,
    phone: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = serde_json::Map::new();
    if let Some(v) = first_name {
        body.insert("first_name".into(), json!(v));
    }
    if let Some(v) = last_name {
        body.insert("last_name".into(), json!(v));
    }
    if let Some(v) = phone {
        body.insert("phone".into(), json!(v));
    }
    let r = api
        .put(
            "/users/me/profile",
            cookie,
            Some(serde_json::Value::Object(body)),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-408: upload (or replace) the signed-in user's avatar. Relays the raw
/// bytes as a multipart file part to `POST /users/me/avatar`; the API sniffs the
/// real MIME from content, so the declared `mime` here is advisory. The API
/// re-validates type, size, and dimensions.
pub async fn upload_avatar(
    api: &Api,
    cookie: Option<&str>,
    filename: &str,
    mime: &str,
    bytes: Vec<u8>,
) -> Result<(), ApiError> {
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name(filename.to_string())
        .mime_str(mime)
        .map_err(|e| ApiError::network(format!("invalid avatar mime: {e}")))?;
    let form = reqwest::multipart::Form::new().part("avatar", part);
    let r = api.post_form("/users/me/avatar", cookie, form).await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-408: remove the signed-in user's avatar (`DELETE /users/me/avatar`).
pub async fn remove_avatar(api: &Api, cookie: Option<&str>) -> Result<(), ApiError> {
    let r = api.delete("/users/me/avatar", cookie, None).await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-408: stream the signed-in user's avatar bytes for the `/me/avatar` BFF
/// proxy. Returns the raw `reqwest::Response` (status/headers/body relayed by the
/// handler) so a same-origin `<img>` can load it with the session cookie.
pub async fn fetch_avatar(api: &Api, cookie: Option<&str>) -> Result<reqwest::Response, ApiError> {
    api.get_stream("/users/me/avatar", cookie).await
}

pub async fn change_password(
    api: &Api,
    cookie: Option<&str>,
    current: &str,
    new: &str,
    totp_code: &str,
) -> Result<(), ApiError> {
    let mut body = json!({ "current_password": current, "new_password": new });
    if !totp_code.is_empty() {
        body["totp_code"] = json!(totp_code);
    }
    let r = api.put("/users/me/password", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

/// Returns whether the API says re-login is required, plus any cleared cookies.
pub async fn request_email_change(
    api: &Api,
    cookie: Option<&str>,
    new_email: &str,
    current_password: &str,
    totp_code: &str,
) -> Result<(bool, Vec<String>), ApiError> {
    let mut body = json!({ "new_email": new_email });
    if !current_password.is_empty() {
        body["current_password"] = json!(current_password);
    }
    if !totp_code.is_empty() {
        body["totp_code"] = json!(totp_code);
    }
    let r = api.post("/users/me/email", cookie, Some(body)).await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?;
    let relogin = data
        .get("requires_relogin")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    Ok((relogin, cookies))
}

pub async fn confirm_email_change(api: &Api, token: &str) -> Result<(), ApiError> {
    let r = api
        .post(
            "/users/me/email/confirm",
            None,
            Some(json!({ "token": token })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Returns the granted membership tier string.
pub async fn confirm_email_verification(api: &Api, token: &str) -> Result<String, ApiError> {
    let r = api
        .post(
            "/users/me/email/verify/confirm",
            None,
            Some(json!({ "token": token })),
        )
        .await?;
    let data = ok_data(&r)?;
    Ok(data
        .get("membership_tier")
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string())
}

pub async fn request_email_verification(api: &Api, cookie: Option<&str>) -> Result<(), ApiError> {
    let r = api.post("/users/me/email/verify", cookie, None).await?;
    ok_data(&r).map(|_| ())
}

pub async fn delete_account(
    api: &Api,
    cookie: Option<&str>,
    password: &str,
    totp: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    let body = match totp {
        Some(c) => json!({ "password": password, "totp_code": c }),
        None => json!({ "password": password }),
    };
    let r = api.delete("/users/me", cookie, Some(body)).await?;
    let cookies = r.set_cookies.clone();
    ok_data(&r)?;
    Ok(cookies)
}

// --- 2FA management ---------------------------------------------------------

pub async fn setup_2fa(
    api: &Api,
    cookie: Option<&str>,
) -> Result<TwoFactorSetupResponse, ApiError> {
    parse(api.post("/auth/2fa/setup", cookie, None).await?)
}

pub async fn confirm_2fa(
    api: &Api,
    cookie: Option<&str>,
    code: &str,
) -> Result<RecoveryCodesResponse, ApiError> {
    parse(
        api.post("/auth/2fa/confirm", cookie, Some(json!({ "code": code })))
            .await?,
    )
}

pub async fn status_2fa(
    api: &Api,
    cookie: Option<&str>,
) -> Result<TwoFactorStatusResponse, ApiError> {
    parse(api.get("/auth/2fa/status", cookie).await?)
}

/// BUNYIP-355: begin an authenticator re-key (step-up: password + a current
/// code). Stages a new secret and returns its QR/secret; the old authenticator
/// keeps working until `confirm_rekey`.
pub async fn begin_rekey(
    api: &Api,
    cookie: Option<&str>,
    password: &str,
    totp_code: &str,
) -> Result<TwoFactorSetupResponse, ApiError> {
    let mut body = json!({ "password": password });
    if !totp_code.is_empty() {
        body["totp_code"] = json!(totp_code);
    }
    parse(api.post("/auth/2fa/rekey", cookie, Some(body)).await?)
}

/// BUNYIP-355: confirm the re-key with a code from the new authenticator; swaps
/// the pending secret in and returns fresh recovery codes.
pub async fn confirm_rekey(
    api: &Api,
    cookie: Option<&str>,
    code: &str,
) -> Result<RecoveryCodesResponse, ApiError> {
    parse(
        api.post(
            "/auth/2fa/rekey/confirm",
            cookie,
            Some(json!({ "code": code })),
        )
        .await?,
    )
}

pub async fn disable_2fa(
    api: &Api,
    cookie: Option<&str>,
    password: &str,
    totp_code: &str,
) -> Result<(), ApiError> {
    let mut body = json!({ "password": password });
    if !totp_code.is_empty() {
        body["totp_code"] = json!(totp_code);
    }
    let r = api.post("/auth/2fa/disable", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

pub async fn regenerate_recovery_codes(
    api: &Api,
    cookie: Option<&str>,
    password: &str,
) -> Result<RecoveryCodesResponse, ApiError> {
    parse(
        api.post(
            "/auth/2fa/recovery-codes",
            cookie,
            Some(json!({ "password": password })),
        )
        .await?,
    )
}
