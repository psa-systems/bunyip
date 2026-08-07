//! Admin panel: Feedback.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::{AdminFeedbackDetail, FeedbackAttachmentMeta, FeedbackStatus};
use crate::handlers::{admin_guard, admin_response};
use crate::util::{rel_time, urlenc};
use crate::views::ui::{badge, button_class, empty_state, error_box, icon, pager};
use crate::web::{redirect_cookies, AppState};

use super::with_attachment_hardening;
use super::PageQuery;

/// Top-of-page tabs that bucket the feedback queue by triage state.
/// Active is the working queue (new/reviewed/responded, not spam).
/// Closed is the resolved bin (status=closed, not spam). Spam is
/// quarantine. Archive is the long-term cold storage (BUNYIP-85).
/// BUNYIP-92 added Closed + Spam so "Close" produces a visible effect
/// (row leaves Active, lands in Closed) and spam never clutters
/// triage.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum FeedbackTab {
    Active,
    Closed,
    Spam,
    Archive,
}

impl FeedbackTab {
    /// Bucket string passed to the bunyip-api list endpoint.
    pub(super) fn bucket(self) -> &'static str {
        match self {
            FeedbackTab::Active => "active",
            FeedbackTab::Closed => "closed",
            FeedbackTab::Spam => "spam",
            FeedbackTab::Archive => "active", // unused; archive has its own endpoint
        }
    }

    /// Path used to return to this tab after a row action (so the
    /// admin lands back on the same view they clicked from).
    pub(super) fn path(self) -> &'static str {
        match self {
            FeedbackTab::Active => "/admin/feedback",
            FeedbackTab::Closed => "/admin/feedback/closed",
            FeedbackTab::Spam => "/admin/feedback/spam",
            FeedbackTab::Archive => "/admin/feedback/archive",
        }
    }

    /// Slug for the detail page's `?from=` param, tying a detail view back to
    /// the list tab it was opened from so its actions redirect there
    /// (BUNYIP-422). Distinct from [`bucket`](Self::bucket), which collapses
    /// Archive onto the active list endpoint; this preserves Archive.
    pub(super) fn query_slug(self) -> &'static str {
        match self {
            FeedbackTab::Active => "active",
            FeedbackTab::Closed => "closed",
            FeedbackTab::Spam => "spam",
            FeedbackTab::Archive => "archive",
        }
    }

    /// Parse the `?from=` slug back into a tab; unknown / absent defaults to
    /// Active (the safe fallback, matching [`from_tab_path`]).
    pub(super) fn from_query(from: Option<&str>) -> FeedbackTab {
        match from.unwrap_or("active") {
            "closed" => FeedbackTab::Closed,
            "spam" => FeedbackTab::Spam,
            "archive" => FeedbackTab::Archive,
            _ => FeedbackTab::Active,
        }
    }
}

fn feedback_tabs(current: FeedbackTab) -> Markup {
    let tab_class = |selected: bool| {
        if selected {
            "border-b-2 border-primary px-3 py-2 text-sm font-semibold text-foreground"
        } else {
            "border-b-2 border-transparent px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
        }
    };
    html! {
        nav class="flex items-center gap-2 border-b border-border/50" aria-label="Feedback view" {
            a href="/admin/feedback" class=(tab_class(current == FeedbackTab::Active)) { "Active" }
            a href="/admin/feedback/closed" class=(tab_class(current == FeedbackTab::Closed)) { "Closed" }
            a href="/admin/feedback/spam" class=(tab_class(current == FeedbackTab::Spam)) { "Spam" }
            a href="/admin/feedback/archive" class=(tab_class(current == FeedbackTab::Archive)) { "Archive" }
        }
    }
}

pub async fn feedback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Active).await
}

/// GET /admin/feedback/closed - BUNYIP-92. Rows where the admin clicked
/// Close (status=closed) land here, out of the active triage queue.
pub async fn feedback_closed(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Closed).await
}

/// GET /admin/feedback/spam - BUNYIP-92. Honeypot-detected rows plus
/// any admin-flagged spam. The default Active tab never surfaces these
/// (the repository now filters is_spam=false).
pub async fn feedback_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Spam).await
}

async fn render_feedback_list(
    st: AppState,
    headers: HeaderMap,
    q: PageQuery,
    tab: FeedbackTab,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback(&st.api, c.forward.as_deref(), page, 20, tab.bucket())
        .await
        .ok();
    let reachable = data.is_some();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let (section_title, empty_msg) = match tab {
        FeedbackTab::Active => ("Submissions", "No feedback yet"),
        FeedbackTab::Closed => ("Closed", "No closed feedback"),
        FeedbackTab::Spam => ("Spam", "No spam"),
        FeedbackTab::Archive => ("Archive", "Archive is empty"),
    };

    let content = html! {
        div class="space-y-6" {
            div class="flex items-start justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Feedback" } p class="mt-2 text-muted-foreground" { "Triage submitted feedback." } }
                a href="/admin/feedback/export" class=(button_class("outline", "sm", "")) { "Export CSV" }
            }
            (feedback_tabs(tab))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { (section_title) } }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load feedback."))
                    } @else if items.is_empty() {
                        (empty_state("message-square-quote", empty_msg, None))
                    } @else {
                        div class="divide-y" {
                            @for f in &items {
                                (feedback_row(f, tab))
                            }
                        }
                    }
                    (pager(tab.path(), "page", page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/feedback", "Feedback", content)
}

/// Inline status chip for a feedback row / detail header, mirroring the
/// users-list verification indicator (icon + short label, color-coded) so the
/// two admin lists read the same (BUNYIP-422).
fn feedback_status_chip(status: &FeedbackStatus) -> Markup {
    let (classes, icon_name, label) = match status {
        FeedbackStatus::New => ("text-amber-700 dark:text-amber-400", "alert-circle", "New"),
        FeedbackStatus::Reviewed => (
            "text-teal-600 dark:text-teal-400",
            "check-circle",
            "Reviewed",
        ),
        FeedbackStatus::Responded => ("text-teal-600 dark:text-teal-400", "mail", "Responded"),
        FeedbackStatus::Closed => ("text-muted-foreground", "check", "Closed"),
    };
    html! {
        span class={ "inline-flex items-center gap-1 text-xs font-medium " (classes) } {
            (icon(icon_name, "h-4 w-4")) (label)
        }
    }
}

/// One feedback row: a whole-row link into the detail view (BUNYIP-422),
/// matching the users-list row-as-link pattern. The row surfaces subject,
/// submitter identity, source page, a message excerpt, the relative
/// submission time, and a status chip - no inline action buttons. All triage
/// actions moved to the detail page ([`feedback_detail_actions`]); the
/// `?from=` param carries the tab slug so those actions redirect back to the
/// view the admin came from.
pub(super) fn feedback_row(
    f: &crate::api::types::AdminFeedbackSummary,
    tab: FeedbackTab,
) -> Markup {
    let name = f.name.clone().filter(|s| !s.trim().is_empty());
    let email = f.email_masked.clone().filter(|s| !s.trim().is_empty());
    let identity = match (name.as_deref(), email.as_deref()) {
        (Some(n), Some(e)) => Some(format!("{n} · {e}")),
        (Some(n), None) => Some(n.to_string()),
        (None, Some(e)) => Some(e.to_string()),
        (None, None) => None,
    };
    let from_path = f
        .page_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "/feedback");
    html! {
        a href=(format!("/admin/feedback/{}?from={}", f.id, tab.query_slug()))
          class="flex items-center gap-4 py-3 px-2 -mx-2 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2" {
            div class="min-w-0 flex-1" {
                p class="font-medium truncate" {
                    (f.subject.clone().unwrap_or_else(|| "(no subject)".into()))
                }
                @if let Some(line) = &identity {
                    p class="text-xs text-muted-foreground truncate" { (line) }
                }
                @if let Some(p) = from_path {
                    p class="text-xs text-muted-foreground truncate" { "From: " (p) }
                }
                p class="text-sm text-muted-foreground truncate" { (f.message_excerpt) }
                p class="text-xs text-muted-foreground" { (rel_time(&f.created_at)) }
            }
            div class="flex items-center gap-3 shrink-0" {
                (feedback_status_chip(&f.status))
                (icon("chevron-right", "h-4 w-4 text-muted-foreground"))
            }
        }
    }
}

/// The tab-aware triage actions for one feedback item, shown on the detail
/// page (BUNYIP-422 moved these off the list rows). Mirrors the previous
/// per-row action set: Active gets review / close / archive / spam / delete,
/// Closed gets reopen / archive / spam / delete, Spam gets not-spam / archive
/// / delete, Archive gets delete. Each POSTs a `from` hidden field carrying
/// the tab slug so the handler redirects back to the list view the admin came
/// from.
pub(super) fn feedback_detail_actions(
    id: &str,
    status: &FeedbackStatus,
    tab: FeedbackTab,
) -> Markup {
    let already_reviewed = matches!(status, FeedbackStatus::Reviewed);
    let review_action = if already_reviewed { "new" } else { "reviewed" };
    let review_label = if already_reviewed {
        "Un-review"
    } else {
        "Reviewed"
    };
    let from = tab.query_slug();
    html! {
        div class="flex flex-wrap items-center gap-2" {
            @match tab {
                FeedbackTab::Active => {
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value=(review_action);
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { (review_label) }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value="closed";
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Close" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/mark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Mark as spam" }
                    }
                }
                FeedbackTab::Closed => {
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value="new";
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Re-open" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/mark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Mark as spam" }
                    }
                }
                FeedbackTab::Spam => {
                    form method="post" action=(format!("/admin/feedback/{id}/unmark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Not spam" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                }
                FeedbackTab::Archive => {}
            }
            form method="post" action=(format!("/admin/feedback/{id}/delete"))
                data-confirm="Delete this feedback permanently? This cannot be undone." {
                input type="hidden" name="from" value=(from);
                button type="submit" class=(button_class("outline", "sm", "text-destructive-text hover:text-destructive-text")) { "Delete" }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct StatusForm {
    pub status: String,
    /// BUNYIP-92: the tab slug (active/closed/spam) the admin clicked
    /// from, so we redirect back to that view with a toast confirming
    /// the action.
    #[serde(default)]
    pub from: Option<String>,
}

/// Map a `from` form value to the tab path the BFF redirects back to
/// after a row action. Unknown values default to `/admin/feedback`
/// (Active) which is the safe fallback.
fn from_tab_path(from: Option<&str>) -> &'static str {
    match from.unwrap_or("active") {
        "closed" => "/admin/feedback/closed",
        "spam" => "/admin/feedback/spam",
        "archive" => "/admin/feedback/archive",
        _ => "/admin/feedback",
    }
}

pub async fn feedback_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<StatusForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let status = match f.status.as_str() {
        "reviewed" => FeedbackStatus::Reviewed,
        "responded" => FeedbackStatus::Responded,
        "closed" => FeedbackStatus::Closed,
        _ => FeedbackStatus::New,
    };
    let toast = match status {
        FeedbackStatus::Closed => "Closed",
        FeedbackStatus::Reviewed => "Marked reviewed",
        FeedbackStatus::New => "Re-opened",
        FeedbackStatus::Responded => "Marked responded",
    };
    let target =
        match admin_api::update_feedback_status(&st.api, c.forward.as_deref(), &id, status).await {
            Ok(()) => format!(
                "{}?toast_ok={}",
                from_tab_path(f.from.as_deref()),
                urlencoding::encode(toast),
            ),
            Err(_) => format!(
                "{}?toast_err=Could%20not%20update%20status",
                from_tab_path(f.from.as_deref()),
            ),
        };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct FromForm {
    #[serde(default)]
    pub from: Option<String>,
}

/// POST /admin/feedback/:id/mark-spam (BUNYIP-92).
pub async fn feedback_mark_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::mark_feedback_spam(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!(
            "{}?toast_ok=Marked%20as%20spam",
            from_tab_path(f.from.as_deref()),
        ),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20mark%20spam",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/unmark-spam (BUNYIP-92).
pub async fn feedback_unmark_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unmark_feedback_spam(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!(
            "{}?toast_ok=Restored%20from%20spam",
            from_tab_path(f.from.as_deref()),
        ),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20unmark%20spam",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/archive (BUNYIP-93). Per-row archive: the
/// row moves out of `feedback` and into `feedback_archive`. Reversible
/// from the Archive tab via the existing Restore button (BUNYIP-85).
pub async fn feedback_archive_action(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::archive_feedback(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("{}?toast_ok=Archived", from_tab_path(f.from.as_deref()),),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20archive",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/delete (BUNYIP-92). Hard delete, gated by a
/// JS confirm() on the form; the BFF does NOT add a second confirmation.
pub async fn feedback_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_feedback(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("{}?toast_ok=Deleted", from_tab_path(f.from.as_deref()),),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20delete",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// GET /admin/feedback/export
///
/// BFF proxy for the bunyip-api CSV export. The browser cannot hit
/// `<api>/v1/admin/feedback/export` directly (separate origin, the
/// session cookie is scoped to this app), so the "Export CSV" anchor on
/// the admin feedback page points here. We re-auth via `admin_guard`,
/// forward the session cookie to the API at `/admin/feedback/export`,
/// and stream the response body back with the upstream `Content-Type`
/// and `Content-Disposition` so the browser drives the download.
///
/// Pattern mirrors `dashboard::download_asset`; see its doc comment for
/// the upstream-status / fallback rationale.
pub async fn feedback_export(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/admin/feedback/export", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/csv")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"feedback.csv\"".to_string());
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let content_length = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/admin/feedback", &c.set_cookies))
        }
        // 401 forces re-auth; everything else bounces back to the list
        // (lost privileges, upstream outage) so the browser never saves an
        // error blob as `feedback.csv`.
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies("/admin/feedback", &c.set_cookies),
    }
}

/// GET /admin/feedback/:id
///
/// Detail subpage for a single feedback submission. Shows the unmasked
/// email (callers already pass `admin_guard`), full message, captured
/// `page_path`, current status, and either the existing admin response
/// or an inline form to send one.
pub async fn feedback_detail(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FeedbackDetailQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-422: the list rows link here with `?from=<tab>` so the triage
    // actions (now hosted on this page) render for the right tab and redirect
    // back to the list the admin came from.
    let tab = FeedbackTab::from_query(q.from.as_deref());
    let detail = match admin_api::feedback_detail(&st.api, c.forward.as_deref(), &id).await {
        Ok(d) => d,
        Err(_) => return redirect_cookies(tab.path(), &c.set_cookies),
    };
    let content = feedback_detail_view(&detail, tab);
    admin_response(&c, &user, "/admin/feedback", "Feedback", content)
}

/// Query for the feedback detail page. `from` names the list tab the admin
/// clicked from (BUNYIP-422); absent / unknown falls back to Active.
#[derive(Deserialize)]
pub struct FeedbackDetailQuery {
    #[serde(default)]
    pub from: Option<String>,
}

pub(super) fn feedback_detail_view(f: &AdminFeedbackDetail, tab: FeedbackTab) -> Markup {
    // BUNYIP-94: render the masked email, never the raw one. Admins do
    // not need the raw address to reply (the API holds it and routes the
    // response server-side); leaking the raw address on the detail page
    // would violate the same masking posture the row list already uses.
    let identity_line = match (
        f.name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        f.email_masked
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(n), Some(e)) => Some(format!("{n} · {e}")),
        (Some(n), None) => Some(n.to_string()),
        (None, Some(e)) => Some(e.to_string()),
        (None, None) => None,
    };
    // BUNYIP-94: explicit signal when the row has no email at all. The
    // reply form will still save the response to the DB, but no email
    // can be delivered. Surfacing this means an admin does not silently
    // assume the submitter received the reply.
    let has_email = f
        .email
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let from_path = f
        .page_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "/feedback");
    html! {
        div class="space-y-6 max-w-3xl" {
            div class="flex items-center justify-between gap-4" {
                div {
                    h1 class="text-3xl font-bold" { (f.subject.clone().unwrap_or_else(|| "(no subject)".into())) }
                    p class="mt-2 text-muted-foreground text-sm" {
                        a href=(tab.path()) class="hover:underline" { "← Back to feedback" }
                    }
                }
                (feedback_status_chip(&f.status))
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6 space-y-4" {
                    @if let Some(line) = &identity_line {
                        div { h3 class="text-sm font-semibold" { "From" } p class="text-sm text-muted-foreground" { (line) } }
                    }
                    @if let Some(p) = from_path {
                        div { h3 class="text-sm font-semibold" { "Page" } p class="text-sm text-muted-foreground" { (p) } }
                    }
                    @if !f.tags.is_empty() {
                        div {
                            h3 class="text-sm font-semibold" { "Tags" }
                            div class="mt-1 flex flex-wrap gap-1.5" {
                                @for t in &f.tags { (badge("outline", t)) }
                            }
                        }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Message" }
                        // Preserve newlines from the original submission; the
                        // submitter's paragraph breaks carry meaning when
                        // describing a repro.
                        p class="text-sm whitespace-pre-wrap" { (f.message) }
                    }
                    @if !f.attachments.is_empty() {
                        (feedback_attachments_view(&f.id, &f.attachments))
                    }
                    div { h3 class="text-sm font-semibold" { "Received" } p class="text-sm text-muted-foreground" { (rel_time(&f.created_at)) } }
                    // BUNYIP-411: request metadata for spam tracing. Shown only
                    // when captured (dev / direct-hit submissions resolve no
                    // forwarded IP). Maud escapes both values.
                    // BUNYIP-436: link the captured IP into the existing ban
                    // flow (the /admin/ip-bans add form prefills from `?ip=`),
                    // so a repeat spam source can be banned in one hop.
                    @if let Some(ip) = f.submitter_ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        div {
                            h3 class="text-sm font-semibold" { "IP address" }
                            p class="text-sm" {
                                a href=(format!("/admin/ip-bans?ip={}", urlenc(ip))) class="font-mono text-primary-text underline-offset-4 hover:underline" title="Ban or look up this address" { (ip) }
                            }
                        }
                    }
                    @if let Some(ua) = f.user_agent.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        div { h3 class="text-sm font-semibold" { "User agent" } p class="text-sm text-muted-foreground break-all" { (ua) } }
                    }
                }
            }
            // BUNYIP-422: the triage actions now live here (moved off the
            // list rows). They are tab-aware and each POSTs `from` = the tab
            // slug, so on success the admin lands back on the list view they
            // came from, not on a detail page for a row they just deleted.
            (feedback_detail_actions(&f.id, &f.status, tab))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Response" } }
                div class="p-6 pt-0 space-y-4" {
                    // BUNYIP-94: when the submitter left no email, the
                    // reply form still saves the response to the DB but
                    // no email goes out. Make that explicit so admins do
                    // not silently assume the submitter received it.
                    @if !has_email {
                        div class="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300" {
                            "No email on record - the submitter did not provide an address. Your response will be saved but cannot be delivered."
                        }
                    }
                    // BUNYIP-123: a sent response is editable and
                    // resendable rather than one-shot. The respond route
                    // upserts admin_response, so re-submitting the
                    // (pre-filled) form overwrites the stored reply and,
                    // when an email is on record, re-delivers it - letting
                    // an admin fix a typo or wrong reply. When a response
                    // already exists, show when it was last sent above the
                    // form and pre-fill the textarea with the current text.
                    // No-email guard: `respond_to_feedback` on the API side
                    // just skips the email send when the submitter left no
                    // address, so the form does NOT need to gate on
                    // email_present here. The status update still happens
                    // either way. On success the POST bounces back to this
                    // same detail page with a `?toast_ok=` confirmation.
                    @let existing_response = f.admin_response.as_deref().map(str::trim).filter(|s| !s.is_empty());
                    @if existing_response.is_some() {
                        @if let Some(at) = &f.responded_at {
                            p class="text-xs text-muted-foreground" { "Sent " (rel_time(at)) }
                        }
                    }
                    form method="post" action=(format!("/admin/feedback/{}/respond", f.id)) class="space-y-3" {
                        div class="grid gap-2" {
                            label for="response" class="text-sm font-medium" { "Reply to the submitter" }
                            textarea id="response" name="response" rows="6" required placeholder="Type a response. The submitter will receive this verbatim by email." class="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {
                                @if let Some(resp) = existing_response { (resp) }
                            }
                        }
                        div class="flex justify-end" {
                            button type="submit" class=(button_class("default", "default", "gap-2")) {
                                @if existing_response.is_some() { "Resend response" } @else { "Send response" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct RespondForm {
    pub response: String,
}

/// POST /admin/feedback/:id/respond
pub async fn feedback_respond(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(body): Form<RespondForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let response = body.response.trim();
    if response.is_empty() {
        // Empty body: short-circuit and reload the detail page; the user
        // can re-type. No toast - they will see the empty textarea and
        // figure it out.
        return redirect_cookies(&format!("/admin/feedback/{id}"), &c.set_cookies);
    }
    // BUNYIP-117: bound the admin response at the web edge. The body is
    // emailed verbatim and stored in feedback_responses (TEXT); 16k chars
    // is generous for a support reply while still rejecting a runaway
    // paste. Authoritative validation happens in
    // `services::feedback::respond` once the API tightens its own bound.
    const RESPONSE_MAX: usize = 16_000;
    if response.len() > RESPONSE_MAX {
        return redirect_cookies(
            &format!(
                "/admin/feedback/{id}?toast_err=Response%20must%20be%20{RESPONSE_MAX}%20characters%20or%20fewer"
            ),
            &c.set_cookies,
        );
    }
    let target =
        match admin_api::respond_to_feedback(&st.api, c.forward.as_deref(), &id, response).await {
            Ok(()) => format!("/admin/feedback/{id}?toast_ok=Response%20sent"),
            Err(_) => format!("/admin/feedback/{id}?toast_err=Could%20not%20send%20response"),
        };
    redirect_cookies(&target, &c.set_cookies)
}

/// GET /admin/feedback/archive
pub async fn feedback_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback_archive(&st.api, c.forward.as_deref(), page, 20)
        .await
        .ok();
    let reachable = data.is_some();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let content = html! {
        div class="space-y-6" {
            div class="flex items-start justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Feedback" } p class="mt-2 text-muted-foreground" { "Archived submissions. Restore moves a row back to the active list." } }
                a href="/admin/feedback/export" class=(button_class("outline", "sm", "")) { "Export CSV" }
            }
            (feedback_tabs(FeedbackTab::Archive))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Archived" } }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load archived feedback."))
                    } @else {
                    div class="divide-y" {
                        @for a in &items {
                            @let name = a.name.clone().filter(|s| !s.trim().is_empty());
                            @let email = a.email.clone().filter(|s| !s.trim().is_empty());
                            @let identity = match (name.as_deref(), email.as_deref()) {
                                (Some(n), Some(e)) => Some(format!("{n} · {e}")),
                                (Some(n), None) => Some(n.to_string()),
                                (None, Some(e)) => Some(e.to_string()),
                                (None, None) => None,
                            };
                            div class="py-3 flex items-start justify-between gap-4" {
                                div class="min-w-0" {
                                    p class="font-medium truncate" { (a.subject.clone().unwrap_or_else(|| "(no subject)".into())) }
                                    @if let Some(line) = &identity {
                                        p class="text-xs text-muted-foreground truncate" { (line) }
                                    }
                                    p class="text-sm text-muted-foreground truncate" { (a.message_excerpt) }
                                    p class="text-xs text-muted-foreground" {
                                        "Archived " (rel_time(&a.archived_at))
                                        @if let Some(orig) = &a.original_status {
                                            " · was " (orig)
                                        }
                                    }
                                }
                                div class="flex items-center gap-2 shrink-0" {
                                    form method="post" action=(format!("/admin/feedback/archive/{}/restore", a.id)) {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Restore" }
                                    }
                                }
                            }
                        }
                        @if items.is_empty() { (empty_state("message-square-quote", "Archive is empty", None)) }
                    }
                    (pager("/admin/feedback/archive", "page", page, total_pages))
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/feedback", "Feedback", content)
}

/// Render the attachments block on the feedback detail page. Image
/// MIMEs get an inline `<img>` thumbnail loaded from the same BFF
/// proxy URL; other MIMEs (text/plain) stay as a plain download link
/// with the filename and a human-readable size.
fn feedback_attachments_view(feedback_id: &str, atts: &[FeedbackAttachmentMeta]) -> Markup {
    html! {
        div {
            h3 class="text-sm font-semibold" { "Attachments" }
            div class="mt-2 grid gap-3 sm:grid-cols-2" {
                @for a in atts {
                    @let href = format!(
                        "/admin/feedback/{}/attachments/{}",
                        feedback_id, a.id,
                    );
                    @let is_image = a.mime_type.starts_with("image/");
                    div class="rounded-md border border-border/60 p-3 flex gap-3 items-start" {
                        @if is_image {
                            a href=(href) target="_blank" rel="noopener" class="shrink-0" {
                                img src=(href) alt=(a.filename)
                                    class="h-20 w-20 rounded object-cover bg-muted";
                            }
                        }
                        div class="min-w-0 flex-1" {
                            a href=(href) class="text-sm font-medium hover:underline truncate block" { (a.filename) }
                            p class="text-xs text-muted-foreground" { (format_size(a.size_bytes)) " · " (a.mime_type) }
                        }
                    }
                }
            }
        }
    }
}

/// Render byte count as KB / MB with one decimal. Bytes-only for tiny
/// (rare) values. Used in the attachments list.
fn format_size(bytes: i64) -> String {
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{:.1} MB", b / (1024.0 * 1024.0))
    }
}

/// GET /admin/feedback/:id/attachments/:attachment_id
///
/// BFF proxy for a single feedback attachment. The browser cannot hit
/// bunyip-api directly (cross-origin cookie), so the `<img>` and
/// download anchors on the detail page point here. Re-auth via
/// `admin_guard`, forward to the API at
/// `/admin/feedback/{id}/attachments/{attachment_id}`, stream the
/// response body back with the upstream `Content-Type` and
/// `Content-Disposition`. Pattern mirrors `feedback_export` and
/// `dashboard::download_asset`.
pub async fn feedback_attachment(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((feedback_id, attachment_id)): Path<(String, String)>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let path = format!("/admin/feedback/{feedback_id}/attachments/{attachment_id}");
    match st.api.get_stream(&path, c.forward.as_deref()).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment".to_string());
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let content_length = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| {
                    redirect_cookies(&format!("/admin/feedback/{feedback_id}"), &c.set_cookies)
                })
        }
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies(&format!("/admin/feedback/{feedback_id}"), &c.set_cookies),
    }
}

/// POST /admin/feedback/archive/:archive_id/restore
pub async fn feedback_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(archive_id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::restore_feedback(&st.api, c.forward.as_deref(), &archive_id).await
    {
        Ok(()) => "/admin/feedback/archive?toast_ok=Restored".to_string(),
        Err(_) => "/admin/feedback/archive?toast_err=Could%20not%20restore".to_string(),
    };
    redirect_cookies(&target, &c.set_cookies)
}
