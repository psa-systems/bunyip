//! Typed auth/account calls. Endpoints that establish or clear a session return
//! the captured `Set-Cookie` strings (`Vec<String>`) so the handler can relay
//! them to the browser.

use serde_json::{json, Value};

use super::types::{
    AuthResponse, RecoveryCodesResponse, SetupStatus, TrustedDeviceInfo, TrustedDeviceList,
    TwoFactorSetupResponse, TwoFactorStatusResponse, User,
};
use super::{ok_data, parse, Api, ApiError};

/// List the signed-in user's trusted devices (BUNYIP-138).
pub async fn list_trusted_devices(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<TrustedDeviceInfo>, ApiError> {
    let list: TrustedDeviceList = parse(api.get("/users/me/trusted-devices", cookie).await?)?;
    Ok(list.devices)
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
    trust_device: bool,
) -> Result<(User, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/2fa/verify",
            cookie,
            Some(json!({
                "challenge_token": challenge_token,
                "code": code,
                "trust_device": trust_device,
            })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let data = ok_data(&r)?.clone();
    let auth: AuthResponse = serde_json::from_value(data).map_err(|e| ApiError {
        status: 0,
        code: "DECODE_ERROR".into(),
        message: e.to_string(),
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
) -> Result<(User, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/register",
            None,
            Some(json!({ "email": email, "password": password })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let auth: AuthResponse = parse(r)?;
    Ok((auth.user, cookies))
}

pub async fn setup(
    api: &Api,
    email: &str,
    password: &str,
) -> Result<(User, Vec<String>), ApiError> {
    let r = api
        .post(
            "/auth/setup",
            None,
            Some(json!({ "email": email, "password": password })),
        )
        .await?;
    let cookies = r.set_cookies.clone();
    let auth: AuthResponse = parse(r)?;
    Ok((auth.user, cookies))
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
    })?;
    Ok((None, Some(auth.user), cookies))
}

// --- account / email / password --------------------------------------------

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

/// Returns the granted subscription tier string.
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
        .get("subscription_tier")
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

pub async fn disable_2fa(api: &Api, cookie: Option<&str>, password: &str) -> Result<(), ApiError> {
    let r = api
        .post(
            "/auth/2fa/disable",
            cookie,
            Some(json!({ "password": password })),
        )
        .await?;
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
