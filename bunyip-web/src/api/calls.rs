//! Non-admin API calls: applications, membership, billing, downloads, feedback.

use serde_json::{json, Value};

use super::types::{
    AppDoc, AppDocSummary, AppDownloadGroup, Application, ApplicationGroup, ApplicationGroupList,
    ApplicationList, CheckoutSessionResponse, DownloadGroups, Membership, PaginatedResponse,
    SessionInfo, StripeInvoice, StripePaymentResponse,
};
use super::{ok_data, parse, Api, ApiError};

// --- sessions ---------------------------------------------------------------

/// A page of the signed-in user's active sessions (BUNYIP-137 / BUNYIP-177).
/// The API returns a `PaginatedResponse<SessionInfo>` inside the data envelope.
pub async fn list_sessions(
    api: &Api,
    cookie: Option<&str>,
    page: i64,
    per_page: i64,
) -> Result<PaginatedResponse<SessionInfo>, ApiError> {
    parse(
        api.get(
            &format!("/users/me/sessions?page={page}&per_page={per_page}"),
            cookie,
        )
        .await?,
    )
}

/// Revoke a single session by id. The API enforces that the session belongs to
/// the caller.
pub async fn revoke_session(api: &Api, cookie: Option<&str>, id: &str) -> Result<(), ApiError> {
    let path = format!("/users/me/sessions/{}", urlencoding::encode(id));
    let r = api.delete(&path, cookie, None).await?;
    ok_data(&r)?;
    Ok(())
}

/// Revoke every session except the caller's current one ("log out all other
/// devices").
pub async fn revoke_other_sessions(api: &Api, cookie: Option<&str>) -> Result<(), ApiError> {
    let r = api
        .post("/users/me/sessions/revoke-others", cookie, None)
        .await?;
    ok_data(&r)?;
    Ok(())
}

// --- applications -----------------------------------------------------------

pub async fn applications(api: &Api, cookie: Option<&str>) -> Result<Vec<Application>, ApiError> {
    let list: ApplicationList = parse(api.get("/applications", cookie).await?)?;
    Ok(list.applications)
}

/// Application groups for grouping the applications page (BUNYIP-100).
pub async fn application_groups(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<ApplicationGroup>, ApiError> {
    let list: ApplicationGroupList = parse(api.get("/application-groups", cookie).await?)?;
    Ok(list.groups)
}

// --- membership -------------------------------------------------------------

pub async fn membership(api: &Api, cookie: Option<&str>) -> Result<Option<Membership>, ApiError> {
    parse(api.get("/memberships/me", cookie).await?)
}

pub async fn checkout(
    api: &Api,
    cookie: Option<&str>,
    price_id: Option<&str>,
) -> Result<CheckoutSessionResponse, ApiError> {
    let body = match price_id {
        Some(id) => json!({ "price_id": id }),
        None => json!({}),
    };
    parse(
        api.post("/memberships/checkout", cookie, Some(body))
            .await?,
    )
}

/// These mutate JWT claims, so relay any rotated cookies.
pub async fn subscribe(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    membership_action(api, cookie, "/memberships/subscribe").await
}
pub async fn cancel(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    membership_action(api, cookie, "/memberships/cancel").await
}
pub async fn cancel_now(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    membership_action(api, cookie, "/memberships/cancel-now").await
}
pub async fn reactivate(api: &Api, cookie: Option<&str>) -> Result<Vec<String>, ApiError> {
    membership_action(api, cookie, "/memberships/reactivate").await
}

async fn membership_action(
    api: &Api,
    cookie: Option<&str>,
    path: &str,
) -> Result<Vec<String>, ApiError> {
    let r = api.post(path, cookie, None).await?;
    let cookies = r.set_cookies.clone();
    ok_data(&r)?;
    Ok(cookies)
}

pub async fn payment_history(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<StripePaymentResponse>, ApiError> {
    parse(api.get("/memberships/payments", cookie).await?)
}

// --- billing ----------------------------------------------------------------

pub async fn invoices(api: &Api, cookie: Option<&str>) -> Result<Vec<StripeInvoice>, ApiError> {
    parse(api.get("/billing/invoices", cookie).await?)
}

// --- downloads --------------------------------------------------------------

pub async fn downloads_all(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<AppDownloadGroup>, ApiError> {
    let g: DownloadGroups = parse(api.get("/downloads", cookie).await?)?;
    Ok(g.groups)
}

/// Proxy a single application download asset. Streams the raw bytes from the
/// API's `/applications/{slug}/downloads/{asset}` (which gates on membership +
/// entitlement) so the BFF can relay them to the browser. Returns the raw
/// `reqwest::Response` untouched; the handler maps status/headers/body. The
/// browser cannot hit the API directly (different origin, cookie scoped here),
/// so this hop is what makes the download link actually serve the binary
/// instead of the web origin's HTML 404 fallback (BUNYIP-64).
pub async fn download_asset(
    api: &Api,
    slug: &str,
    asset_name: &str,
    cookie: Option<&str>,
) -> Result<reqwest::Response, ApiError> {
    let path = format!(
        "/applications/{}/downloads/{}",
        urlencoding::encode(slug),
        urlencoding::encode(asset_name),
    );
    api.get_stream(&path, cookie).await
}

// --- feedback ---------------------------------------------------------------

pub struct FeedbackInput {
    pub name: String,
    pub email: String,
    pub subject: String,
    pub message: String,
    pub tags: Vec<String>,
    pub page_path: String,
    pub website: String,
    /// Zero or more files chosen by the submitter. The API caps at 3 files
    /// of up to 5 MB each (bunyip-api/src/handlers/feedback.rs:161, 151);
    /// the SSR layer enforces the same limits upstream of this struct and
    /// returns an inline error before getting here.
    pub attachments: Vec<FeedbackAttachment>,
}

pub struct FeedbackAttachment {
    pub filename: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

pub async fn submit_feedback(
    api: &Api,
    cookie: Option<&str>,
    input: &FeedbackInput,
) -> Result<(), ApiError> {
    let mut form = reqwest::multipart::Form::new().text("message", input.message.clone());
    if !input.name.is_empty() {
        form = form.text("name", input.name.clone());
    }
    if !input.email.is_empty() {
        form = form.text("email", input.email.clone());
    }
    if !input.subject.is_empty() {
        form = form.text("subject", input.subject.clone());
    }
    if !input.page_path.is_empty() {
        form = form.text("page_path", input.page_path.clone());
    }
    if !input.website.is_empty() {
        form = form.text("website", input.website.clone());
    }
    for tag in &input.tags {
        form = form.text("tags[]", tag.clone());
    }
    // Files. The API identifies file parts by the presence of a
    // `file_name` on the content-disposition (not by part name), so the
    // `attachments` part name is purely descriptive.
    for a in &input.attachments {
        let part = reqwest::multipart::Part::bytes(a.bytes.clone())
            .file_name(a.filename.clone())
            .mime_str(&a.mime)
            .map_err(|e| ApiError::network(format!("invalid attachment mime: {e}")))?;
        form = form.part("attachments", part);
    }
    let r = api.post_form("/feedback", cookie, form).await?;
    let _: &Value = ok_data(&r)?;
    Ok(())
}

// --- application docs (BUNYIP-388, public read) -----------------------------

/// Public: an application's documentation index (page metadata, ordered).
pub async fn app_docs(api: &Api, app_slug: &str) -> Result<Vec<AppDocSummary>, ApiError> {
    parse(
        api.get(
            &format!("/applications/{}/docs", urlencoding::encode(app_slug)),
            None,
        )
        .await?,
    )
}

/// Public: one documentation page by app slug + doc slug.
pub async fn app_doc(api: &Api, app_slug: &str, doc_slug: &str) -> Result<AppDoc, ApiError> {
    parse(
        api.get(
            &format!(
                "/applications/{}/docs/{}",
                urlencoding::encode(app_slug),
                urlencoding::encode(doc_slug)
            ),
            None,
        )
        .await?,
    )
}
