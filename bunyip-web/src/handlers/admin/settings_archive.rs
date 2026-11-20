//! Admin panel: Settings Archive (BUNYIP-715).
//!
//! Super admin downloads a passphrase-sealed archive of every admin-managed
//! setting (BUNYIP-714 core module), or uploads one to preview-then-apply.
//! A successful apply triggers every per-section in-process reload the api
//! performs, so a restore takes effect without a restart (system settings
//! still need a restart per the core module; the UI calls that out).

use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::{header, HeaderMap, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::Value;

use crate::api::admin as admin_api;
use crate::api::types::{
    SettingsArchiveImportPlan, SettingsArchiveImportReport, SettingsArchiveSectionDiff,
};
use crate::api::ApiError;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::password::{password_field, PwField, PwRole};
use crate::views::ui::{button_class, error_box_for};
use crate::web::{redirect_cookies, AppState};

use super::{refuse_non_super_admin, with_attachment_hardening};

const UPLOAD_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct ExportForm {
    pub passphrase: String,
    pub passphrase_confirm: String,
    #[serde(default)]
    pub include_catalog: Option<String>,
    #[serde(default)]
    pub include_oauth_clients: Option<String>,
}

#[derive(Debug)]
struct PageState {
    error: Option<Markup>,
    plan: Option<SettingsArchiveImportPlan>,
    report: Option<SettingsArchiveImportReport>,
}

impl PageState {
    fn empty() -> Self {
        Self {
            error: None,
            plan: None,
            report: None,
        }
    }
}

fn export_card(is_super_admin: bool) -> Markup {
    html! {
        section class="rounded-lg border bg-card p-6 space-y-4" {
            h2 class="text-xl font-semibold" { "Export Settings" }
            p class="text-sm text-muted-foreground" {
                "The file holds every admin-managed setting and the governed "
                "secrets, encrypted under a passphrase. The passphrase is not "
                "stored and cannot be recovered."
            }
            @if is_super_admin {
                form method="post" action="/admin/settings-archive/export" class="space-y-3" {
                    (password_field(
                        "export-passphrase",
                        "passphrase",
                        "Passphrase",
                        PwRole::New,
                        PwField {
                            required: true,
                            autocomplete: Some("new-password"),
                            ..PwField::default()
                        },
                    ))
                    (password_field(
                        "export-passphrase-confirm",
                        "passphrase_confirm",
                        "Confirm passphrase",
                        PwRole::Confirm,
                        PwField {
                            required: true,
                            autocomplete: Some("new-password"),
                            ..PwField::default()
                        },
                    ))
                    label class="flex items-center gap-2 text-sm" {
                        input type="checkbox" name="include_catalog" value="1";
                        "Include the application catalog"
                    }
                    label class="flex items-center gap-2 text-sm" {
                        input type="checkbox" name="include_oauth_clients" value="1";
                        "Include OAuth clients"
                    }
                    button
                        type="submit"
                        class=(button_class("default", "default", ""))
                    { "Download Archive" }
                }
            }
        }
    }
}

fn import_card(is_super_admin: bool, state: &PageState) -> Markup {
    html! {
        section class="rounded-lg border bg-card p-6 space-y-4" {
            h2 class="text-xl font-semibold" { "Import Settings" }
            p class="text-sm text-muted-foreground" {
                "Importing replaces every section the archive contains, "
                "including secrets. Sections the archive does not carry stay "
                "untouched. System settings apply after a restart."
            }
            @if let Some(err) = &state.error {
                (err.clone())
            }
            @if let Some(plan) = &state.plan {
                (render_plan_card(plan))
            }
            @if let Some(report) = &state.report {
                (render_report_card(report))
            }
            @if is_super_admin {
                form
                    method="post"
                    action="/admin/settings-archive/import"
                    enctype="multipart/form-data"
                    class="space-y-3"
                    data-confirm="Import this archive? Unless Preview only is ticked, this replaces this deployment's settings."
                {
                    div class="space-y-1" {
                        label class="text-sm font-medium" for="import-file" { "Archive file" }
                        input
                            id="import-file"
                            name="archive"
                            type="file"
                            accept="application/json"
                            required
                            class=(dashboard_input());
                    }
                    (password_field(
                        "import-passphrase",
                        "passphrase",
                        "Passphrase",
                        PwRole::Current,
                        PwField {
                            required: true,
                            autocomplete: Some("off"),
                            ..PwField::default()
                        },
                    ))
                    label class="flex items-center gap-2 text-sm" {
                        input type="checkbox" name="dry_run" value="1" checked;
                        "Preview only"
                    }
                    button
                        type="submit"
                        class=(button_class("default", "default", ""))
                    { "Import Archive" }
                }
            }
        }
    }
}

fn section_diff_row(d: &SettingsArchiveSectionDiff) -> Markup {
    let any_changes = !d.inserted.is_empty() || !d.updated.is_empty() || !d.deleted.is_empty();
    html! {
        li class="rounded border bg-background p-3 text-sm space-y-1" {
            div class="font-medium" { (d.section) }
            @if d.unchanged || !any_changes {
                p class="text-muted-foreground" { "Unchanged." }
            } @else {
                @if !d.inserted.is_empty() {
                    p { "Inserted (" (d.inserted.len()) "): " (d.inserted.join(", ")) }
                }
                @if !d.updated.is_empty() {
                    p { "Updated (" (d.updated.len()) "): " (d.updated.join(", ")) }
                }
                @if !d.deleted.is_empty() {
                    p { "Deleted (" (d.deleted.len()) "): " (d.deleted.join(", ")) }
                }
            }
            @for note in &d.notes {
                p class="text-muted-foreground italic" { (note) }
            }
        }
    }
}

fn render_plan_card(plan: &SettingsArchiveImportPlan) -> Markup {
    html! {
        div class="rounded border bg-muted/40 p-4 space-y-2" {
            h3 class="text-sm font-semibold" { "Preview" }
            @if plan.sections.is_empty() {
                p class="text-sm text-muted-foreground" { "No changes." }
            } @else {
                ul class="space-y-2" {
                    @for d in &plan.sections {
                        (section_diff_row(d))
                    }
                }
            }
            @if !plan.secret_outcomes.is_empty() {
                p class="text-sm" { "Secrets: " (plan.secret_outcomes.join(", ")) }
            }
            @for note in &plan.notes {
                p class="text-sm text-muted-foreground" { (note) }
            }
        }
    }
}

fn render_report_card(report: &SettingsArchiveImportReport) -> Markup {
    html! {
        div class="rounded border bg-muted/40 p-4 space-y-2" {
            h3 class="text-sm font-semibold" { "Applied" }
            @if !report.plan.sections.is_empty() {
                ul class="space-y-2" {
                    @for d in &report.plan.sections {
                        (section_diff_row(d))
                    }
                }
            }
            ul class="text-sm space-y-1" {
                @for s in &report.steps {
                    li {
                        @if s.applied { "Applied: " } @else { "Failed: " }
                        (s.step)
                        @if let Some(detail) = &s.detail {
                            " - " (detail)
                        }
                    }
                }
            }
            p class="text-sm text-muted-foreground italic" {
                "System settings apply after a restart."
            }
        }
    }
}

fn page_content(is_super_admin: bool, state: &PageState) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Settings Archive" }
                p class="mt-2 text-muted-foreground" {
                    "Download and restore this deployment's admin-managed settings."
                }
            }
            (export_card(is_super_admin))
            (import_card(is_super_admin, state))
        }
    }
}

/// `GET /admin/settings-archive`
pub async fn settings_archive_page(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Response<Body> {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    admin_response(
        &c,
        &user,
        "/admin/settings-archive",
        "Settings Archive",
        page_content(user.is_super_admin, &PageState::empty()),
    )
}

/// `POST /admin/settings-archive/export` - streams the sealed archive back.
pub async fn settings_archive_export(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<ExportForm>,
) -> Response<Body> {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(r) = refuse_non_super_admin(&user, &c, "/admin/settings-archive") {
        return r;
    }

    if body.passphrase != body.passphrase_confirm {
        let err = error_box_for(
            "Passphrases do not match",
            &ApiError {
                status: 422,
                code: "VALIDATION".into(),
                message: "Enter the same passphrase in both fields.".into(),
                retry_after: None,
                request_id: None,
                bucket: None,
            },
        );
        let state = PageState {
            error: Some(err),
            ..PageState::empty()
        };
        return admin_response(
            &c,
            &user,
            "/admin/settings-archive",
            "Settings Archive",
            page_content(user.is_super_admin, &state),
        );
    }

    let req_body = serde_json::json!({
        "passphrase": body.passphrase,
        "include_catalog": body.include_catalog.is_some(),
        "include_oauth_clients": body.include_oauth_clients.is_some(),
    });
    match st
        .api
        .post_stream(
            "/admin/settings-archive/export",
            c.forward.as_deref(),
            &req_body,
        )
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| header::HeaderValue::from_static("application/json"));
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .cloned()
                .unwrap_or_else(|| {
                    header::HeaderValue::from_static(
                        "attachment; filename=\"bunyip-settings.json\"",
                    )
                });
            let content_length = resp.headers().get(header::CONTENT_LENGTH).cloned();
            let mut builder = Response::builder()
                .status(resp.status())
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition)
                .header(header::CACHE_CONTROL, "no-store");
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/admin/settings-archive", &c.set_cookies))
        }
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let message = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.get("message")).cloned())
                .and_then(|m| m.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| text.clone());
            let state = PageState {
                error: Some(error_box_for(
                    "Export failed",
                    &ApiError {
                        status,
                        code: "EXPORT_FAILED".into(),
                        message,
                        retry_after: None,
                        request_id: None,
                        bucket: None,
                    },
                )),
                ..PageState::empty()
            };
            admin_response(
                &c,
                &user,
                "/admin/settings-archive",
                "Settings Archive",
                page_content(user.is_super_admin, &state),
            )
        }
        Err(e) => {
            let state = PageState {
                error: Some(error_box_for("Export failed", &e)),
                ..PageState::empty()
            };
            admin_response(
                &c,
                &user,
                "/admin/settings-archive",
                "Settings Archive",
                page_content(user.is_super_admin, &state),
            )
        }
    }
}

/// `POST /admin/settings-archive/import`
pub async fn settings_archive_import(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response<Body> {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(r) = refuse_non_super_admin(&user, &c, "/admin/settings-archive") {
        return r;
    }

    let mut archive: Option<Value> = None;
    let mut passphrase = String::new();
    let mut dry_run = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("archive") => {
                let bytes = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return error_page(&st, &user, &c, format!("Upload failed: {e}"));
                    }
                };
                if bytes.is_empty() {
                    return error_page(&st, &user, &c, "The uploaded file is empty.".into());
                }
                if bytes.len() > UPLOAD_MAX_BYTES {
                    return error_page(
                        &st,
                        &user,
                        &c,
                        format!(
                            "The file must be {} MB or smaller.",
                            UPLOAD_MAX_BYTES / (1024 * 1024)
                        ),
                    );
                }
                archive = match serde_json::from_slice(&bytes) {
                    Ok(v) => Some(v),
                    Err(_) => {
                        return error_page(
                            &st,
                            &user,
                            &c,
                            "The file is not a settings archive.".into(),
                        );
                    }
                };
            }
            Some("passphrase") => {
                passphrase = field.text().await.unwrap_or_default();
            }
            Some("dry_run") => {
                let v = field.text().await.unwrap_or_default();
                dry_run = !v.is_empty();
            }
            _ => {
                let _ = field.bytes().await;
            }
        }
    }

    let Some(archive) = archive else {
        return error_page(&st, &user, &c, "No archive file was uploaded.".into());
    };

    match admin_api::settings_archive_import(
        &st.api,
        c.forward.as_deref(),
        &archive,
        &passphrase,
        dry_run,
    )
    .await
    {
        Ok(data) => {
            let state = if dry_run {
                PageState {
                    plan: serde_json::from_value(data).ok(),
                    ..PageState::empty()
                }
            } else {
                PageState {
                    report: serde_json::from_value(data).ok(),
                    ..PageState::empty()
                }
            };
            admin_response(
                &c,
                &user,
                "/admin/settings-archive",
                "Settings Archive",
                page_content(user.is_super_admin, &state),
            )
        }
        Err(e) if e.status == 500 && e.code == "PARTIAL_APPLY" => {
            // The api handed back the serialised `ImportReport`; render it under
            // an error-headed card so the admin sees both the applied and the
            // failed steps instead of the generic 5xx line.
            let report: Option<SettingsArchiveImportReport> = serde_json::from_str(&e.message).ok();
            let message = html! {
                div class="rounded border border-destructive/60 bg-destructive/10 p-4 space-y-2" {
                    h3 class="font-semibold" { "Import partly applied" }
                    @if let Some(r) = &report {
                        (render_report_card(r))
                    } @else {
                        p class="text-sm" { "The server reported a partial failure but the report could not be decoded." }
                    }
                }
            };
            tracing::error!(
                code = %e.code,
                "settings-archive import: partial apply"
            );
            let state = PageState {
                error: Some(message),
                ..PageState::empty()
            };
            admin_response(
                &c,
                &user,
                "/admin/settings-archive",
                "Settings Archive",
                page_content(user.is_super_admin, &state),
            )
        }
        Err(e) => {
            let state = PageState {
                error: Some(error_box_for("Import failed", &e)),
                ..PageState::empty()
            };
            admin_response(
                &c,
                &user,
                "/admin/settings-archive",
                "Settings Archive",
                page_content(user.is_super_admin, &state),
            )
        }
    }
}

fn error_page(
    _st: &AppState,
    user: &crate::api::types::User,
    c: &crate::auth::AuthCtx,
    message: String,
) -> Response<Body> {
    let state = PageState {
        error: Some(error_box_for(
            "Import failed",
            &ApiError {
                status: 400,
                code: "IMPORT_INPUT".into(),
                message,
                retry_after: None,
                request_id: None,
                bucket: None,
            },
        )),
        ..PageState::empty()
    };
    admin_response(
        c,
        user,
        "/admin/settings-archive",
        "Settings Archive",
        page_content(user.is_super_admin, &state),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(is_super: bool) -> crate::api::types::User {
        serde_json::from_value(serde_json::json!({
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "a@b",
            "email_verified": true,
            "role": "admin",
            "is_super_admin": is_super,
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    /// Both cards' controls render for a super admin, and the explanatory copy
    /// still renders for a plain admin while the mutating controls are absent.
    #[test]
    fn super_admin_sees_the_forms_plain_admin_sees_only_the_copy() {
        let html = page_content(true, &PageState::empty()).into_string();
        assert!(html.contains("Download Archive"));
        assert!(html.contains("Import Archive"));
        assert!(html.contains("<input"));

        let plain = page_content(false, &PageState::empty()).into_string();
        assert!(plain.contains("Export Settings"));
        assert!(plain.contains("Import Settings"));
        assert!(!plain.contains("Download Archive"));
        assert!(!plain.contains("Import Archive"));
        // No file input renders either.
        assert!(!plain.contains("type=\"file\""));
    }

    /// Every passphrase input comes from `password_field`; none carries
    /// `data-pw-guard` (the archive passphrase rules differ from the login rules).
    #[test]
    fn passphrase_inputs_have_no_pw_guard() {
        let html = page_content(true, &PageState::empty()).into_string();
        assert!(html.contains("name=\"passphrase\""));
        assert!(
            !html.contains("data-pw-guard"),
            "the archive passphrase enforces a different rule set; no data-pw-guard: {html}"
        );
    }

    /// The import form carries `data-confirm` and a checked `Preview only`.
    #[test]
    fn import_form_confirms_and_defaults_to_preview() {
        let html = page_content(true, &PageState::empty()).into_string();
        assert!(html.contains("data-confirm=\""));
        let around_dry = html
            .split("name=\"dry_run\"")
            .nth(1)
            .expect("dry_run input is rendered");
        assert!(
            around_dry.starts_with(" value=\"1\" checked"),
            "dry_run defaults to checked (Preview only): {around_dry}"
        );
    }
}
