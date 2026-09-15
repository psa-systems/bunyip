//! Non-admin API calls: applications, membership, billing, downloads, feedback.

use serde_json::{json, Value};

use super::types::{
    AppDoc, AppDocSummary, AppDownloadGroup, Application, ApplicationGroup, ApplicationGroupList,
    ApplicationList, CheckoutSessionResponse, DocumentedApp, DownloadGroups, Membership,
    MokoshGrant, OrgSubscription, Organization, PaginatedResponse, PricingResponse, SessionInfo,
    StripeInvoice, StripePaymentResponse, Team, TeamMember,
};
use super::{ok_data, parse, parse_bare, Api, ApiError};

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

// --- pricing ----------------------------------------------------------------

/// BUNYIP-487: the public pricing payload. Unauthenticated: it is what the
/// marketing pages render, and the admin Pricing tiers page is its only source.
/// BUNYIP-515: the one endpoint that answers with a bare body, hence
/// `parse_bare` - `parse` looked for a `data` key that is never there and
/// failed every decode.
pub async fn pricing(api: &Api) -> Result<PricingResponse, ApiError> {
    parse_bare(api.get("/pricing", None).await?)
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

/// Public: the applications that have published documentation (BUNYIP-635).
/// Not `applications()`: that endpoint filters `is_hosted = TRUE` and returns
/// none of the apps whose docs the `/docs` hub links.
pub async fn documented_apps(api: &Api) -> Result<Vec<DocumentedApp>, ApiError> {
    parse(api.get("/application-docs", None).await?)
}

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

// -- BUNYIP-691: organizations + teams + grants -----------------------------

/// `GET /v1/organization` - the caller's own org. `Ok(None)` when the caller
/// has no org yet, so the SSR page can render the create form.
pub async fn get_own_organization(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Option<Organization>, ApiError> {
    let resp = api.get("/organization", cookie).await?;
    if resp.status == 404 {
        return Ok(None);
    }
    parse(resp).map(Some)
}

/// `POST /v1/organization` - create the caller's org.
pub async fn create_organization(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
) -> Result<Organization, ApiError> {
    parse(
        api.post("/organization", cookie, Some(json!({ "name": name })))
            .await?,
    )
}

/// `PUT /v1/organization` - rename.
pub async fn update_own_organization(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
) -> Result<Organization, ApiError> {
    parse(
        api.put("/organization", cookie, Some(json!({ "name": name })))
            .await?,
    )
}

/// `GET /v1/organization/teams`.
pub async fn list_teams(api: &Api, cookie: Option<&str>) -> Result<Vec<Team>, ApiError> {
    parse(api.get("/organization/teams", cookie).await?)
}

/// `POST /v1/organization/teams`.
pub async fn create_team(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
    description: Option<&str>,
) -> Result<Team, ApiError> {
    let mut body = json!({ "name": name });
    if let Some(d) = description {
        body["description"] = json!(d);
    }
    parse(api.post("/organization/teams", cookie, Some(body)).await?)
}

/// `PUT /v1/organization/teams/{id}`.
pub async fn update_team(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    name: &str,
    description: Option<&str>,
) -> Result<Team, ApiError> {
    let mut body = json!({ "name": name });
    if let Some(d) = description {
        body["description"] = json!(d);
    }
    parse(
        api.put(
            &format!("/organization/teams/{}", urlencoding::encode(team_id)),
            cookie,
            Some(body),
        )
        .await?,
    )
}

/// `DELETE /v1/organization/teams/{id}`.
pub async fn delete_team(api: &Api, cookie: Option<&str>, team_id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!("/organization/teams/{}", urlencoding::encode(team_id)),
            cookie,
            None,
        )
        .await?;
    ok_data(&r)?;
    Ok(())
}

/// `GET /v1/organization/teams/{id}/members`.
pub async fn list_team_members(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
) -> Result<Vec<TeamMember>, ApiError> {
    parse(
        api.get(
            &format!(
                "/organization/teams/{}/members",
                urlencoding::encode(team_id)
            ),
            cookie,
        )
        .await?,
    )
}

/// `POST /v1/organization/teams/{id}/members`.
pub async fn add_team_member(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    bunyip_user_id: &str,
    role: &str,
) -> Result<TeamMember, ApiError> {
    parse(
        api.post(
            &format!(
                "/organization/teams/{}/members",
                urlencoding::encode(team_id)
            ),
            cookie,
            Some(json!({ "bunyip_user_id": bunyip_user_id, "role": role })),
        )
        .await?,
    )
}

/// `DELETE /v1/organization/teams/{team_id}/members/{bunyip_user_id}`.
pub async fn remove_team_member(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    bunyip_user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!(
                "/organization/teams/{}/members/{}",
                urlencoding::encode(team_id),
                urlencoding::encode(bunyip_user_id)
            ),
            cookie,
            None,
        )
        .await?;
    ok_data(&r)?;
    Ok(())
}

/// `PUT /v1/organization/tier` - the owner picks a tier.
pub async fn set_organization_tier(
    api: &Api,
    cookie: Option<&str>,
    org_tier_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .put(
            "/organization/tier",
            cookie,
            Some(json!({ "org_tier_id": org_tier_id })),
        )
        .await?;
    ok_data(&r)?;
    Ok(())
}

/// `GET /v1/organization/subscription` - the current billing snapshot.
pub async fn get_org_subscription(
    api: &Api,
    cookie: Option<&str>,
) -> Result<OrgSubscription, ApiError> {
    parse(api.get("/organization/subscription", cookie).await?)
}

/// `POST /v1/organization/subscription` - subscribe against the picked tier.
pub async fn subscribe_org(api: &Api, cookie: Option<&str>) -> Result<OrgSubscription, ApiError> {
    parse(api.post("/organization/subscription", cookie, None).await?)
}

/// `PUT /v1/organization/subscription` - change tier after picking a new one.
pub async fn change_org_tier(api: &Api, cookie: Option<&str>) -> Result<OrgSubscription, ApiError> {
    parse(api.put("/organization/subscription", cookie, None).await?)
}

/// `DELETE /v1/organization/subscription` - cancel at period end.
pub async fn cancel_org_subscription(
    api: &Api,
    cookie: Option<&str>,
) -> Result<OrgSubscription, ApiError> {
    parse(
        api.delete("/organization/subscription", cookie, None)
            .await?,
    )
}

/// `GET /v1/grants?role=owner` - grants the caller has ISSUED.
pub async fn list_issued_grants(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<MokoshGrant>, ApiError> {
    parse(api.get("/grants?role=owner", cookie).await?)
}

/// `GET /v1/grants?role=grantee` - grants the caller has RECEIVED ("Shared
/// with you"). This is what the app switcher's shared list reads.
pub async fn list_received_grants(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<MokoshGrant>, ApiError> {
    parse(api.get("/grants?role=grantee", cookie).await?)
}

/// `POST /v1/grants` - the caller (grantor) creates a grant.
pub async fn create_grant(
    api: &Api,
    cookie: Option<&str>,
    grantee_email: &str,
    mokosh_account_id: &str,
    role: &str,
) -> Result<MokoshGrant, ApiError> {
    parse(
        api.post(
            "/grants",
            cookie,
            Some(json!({
                "grantee_email": grantee_email,
                "mokosh_account_id": mokosh_account_id,
                "role": role,
            })),
        )
        .await?,
    )
}

/// `DELETE /v1/grants/{id}`.
pub async fn revoke_grant(api: &Api, cookie: Option<&str>, grant_id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!("/grants/{}", urlencoding::encode(grant_id)),
            cookie,
            None,
        )
        .await?;
    ok_data(&r)?;
    Ok(())
}
