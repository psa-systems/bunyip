//! Non-admin API calls: applications, membership, billing, downloads, feedback.

use serde_json::{json, Value};

use super::types::{
    AppDownloadGroup, AppDownloadsResponse, Application, ApplicationList, CheckoutSessionResponse,
    DownloadGroups, Membership, StripeInvoice, StripePaymentResponse,
};
use super::{ok_data, parse, Api, ApiError};

// --- applications -----------------------------------------------------------

pub async fn applications(api: &Api, cookie: Option<&str>) -> Result<Vec<Application>, ApiError> {
    let list: ApplicationList = parse(api.get("/applications", cookie).await?)?;
    Ok(list.applications)
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

pub async fn downloads_for_app(
    api: &Api,
    cookie: Option<&str>,
    slug: &str,
) -> Result<AppDownloadsResponse, ApiError> {
    parse(
        api.get(&format!("/applications/{slug}/downloads"), cookie)
            .await?,
    )
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
