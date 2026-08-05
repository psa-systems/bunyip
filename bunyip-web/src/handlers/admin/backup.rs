//! Admin panel: Account backup & restore (BUNYIP-353).

use axum::body::Body;
use axum::extract::{Multipart, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use maud::{html, Markup};

use crate::api::admin as admin_api;
use crate::api::types::{AppRestoreStatus, RestoreReport};
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

use super::with_attachment_hardening;

/// Upper bound on an uploaded backup file. The bundle embeds each entitled
/// app's backup, so it can be larger than a form post but is not unbounded.
/// Matches the API's restore body limit (8 MiB).
const BACKUP_MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// The Integrations "Backup" surface: explains what an account backup contains,
/// offers a one-click download, and accepts an upload to restore. Reached from
/// the Backup add-on tile on `/applications`; admin-gated like the other
/// settings pages.
fn backup_settings_content(report: Option<&RestoreReport>, error: Option<&str>) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Backup & Restore" }
                p class="mt-2 text-muted-foreground" { "Download a portable backup of this account, or restore one from a file. Account state is captured together with each entitled app's data." }
            }

            @if let Some(msg) = error { (error_box(msg)) }
            @if let Some(r) = report { (restore_report_card(r)) }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "What's included" }
                    p class="text-sm text-muted-foreground" { "One JSON bundle covering the account's Bunyip state plus each entitled app." }
                }
                div class="p-6 pt-0" {
                    ul class="list-disc space-y-2 pl-5 text-sm text-muted-foreground" {
                        li { "Account profile (name and phone)." }
                        li { "Entitlements: the apps this account can access." }
                        li { "Per-app data for each entitled app. " span class="text-foreground" { "Mokosh" } " is pending its backup API and is recorded as unavailable until then; unentitled apps are skipped." }
                    }
                }
            }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Download backup" }
                    p class="text-sm text-muted-foreground" { "Generates and downloads the bundle now." }
                }
                div class="p-6 pt-0" {
                    a href="/integrations/backup/download" class=(button_class("default", "default", "")) {
                        (icon("download", "mr-2 h-4 w-4")) "Download backup"
                    }
                }
            }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Restore from backup" }
                    p class="text-sm text-muted-foreground" { "Re-applies the account profile and re-grants the entitlements in the file, then dispatches each entitled app's data to that app. This overwrites the current profile." }
                }
                div class="p-6 pt-0" {
                    form method="post" action="/integrations/backup/restore" enctype="multipart/form-data" class="space-y-4 max-w-md" data-confirm="Restore from this backup file? This overwrites the current account profile and re-grants the entitlements in the file." {
                        div class="space-y-2" {
                            label for="backup" class="text-sm font-medium" { "Backup file (.json)" }
                            input id="backup" type="file" name="backup" accept="application/json,.json" required class=(dashboard_input());
                        }
                        button type="submit" class=(button_class("default", "default", "")) { (icon("upload", "mr-2 h-4 w-4")) "Restore" }
                    }
                }
            }
        }
    }
}

/// Render the outcome of a restore.
fn restore_report_card(r: &RestoreReport) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Restore complete" }
            }
            div class="p-6 pt-0 space-y-3 text-sm" {
                p { "Profile: " @if r.profile_restored { span class="text-foreground" { "restored" } } @else { "unchanged" } }
                p {
                    "Entitlements granted: "
                    @if r.entitlements_granted.is_empty() { "none" }
                    @else { span class="text-foreground" { (r.entitlements_granted.join(", ")) } }
                }
                @if !r.apps.is_empty() {
                    div {
                        p class="font-medium text-foreground" { "Apps" }
                        ul class="mt-1 list-disc space-y-1 pl-5 text-muted-foreground" {
                            @for app in &r.apps {
                                li {
                                    span class="text-foreground" { (app.slug) } ": "
                                    @match &app.status {
                                        AppRestoreStatus::Restored => { "restored" }
                                        AppRestoreStatus::Skipped { reason } => { "skipped (" (reason) ")" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// GET /integrations/backup - the Backup add-on settings page.
pub async fn backup_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = backup_settings_content(None, None);
    admin_response(
        &c,
        &user,
        "/integrations/backup",
        "Backup & Restore · Bunyip",
        content,
    )
}

/// GET /integrations/backup/download - stream the account bundle from the API
/// with its `Content-Disposition` so the browser saves the file. Mirrors
/// `feedback_export`.
pub async fn backup_download(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/account/backup", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"account-backup.json\"".to_string());
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
                .unwrap_or_else(|_| redirect_cookies("/integrations/backup", &c.set_cookies))
        }
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies("/integrations/backup", &c.set_cookies),
    }
}

/// Read the single uploaded `backup` file from a multipart body and parse it as
/// JSON. Mirrors `read_feedback_multipart`'s field loop.
async fn read_backup_upload(multipart: &mut Multipart) -> Result<serde_json::Value, String> {
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return Err("No backup file was uploaded.".into()),
            Err(e) => return Err(format!("Could not read upload: {e}")),
        };
        let is_backup = field.name() == Some("backup");
        // Always drain the field body before advancing to the next one.
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(format!("Could not read the file: {e}")),
        };
        if !is_backup {
            continue;
        }
        if bytes.is_empty() {
            return Err("The uploaded file is empty.".into());
        }
        if bytes.len() > BACKUP_MAX_UPLOAD_BYTES {
            return Err(format!(
                "The backup file must be {} MB or smaller.",
                BACKUP_MAX_UPLOAD_BYTES / (1024 * 1024)
            ));
        }
        return serde_json::from_slice(&bytes)
            .map_err(|_| "That file is not a valid backup (expected JSON).".to_string());
    }
}

/// POST /integrations/backup/restore - parse the uploaded bundle and forward it
/// to the API, then render the resulting report (or an inline error).
pub async fn backup_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let (report, error) = match read_backup_upload(&mut multipart).await {
        Ok(bundle) => match admin_api::restore_account(&st.api, c.forward.as_deref(), bundle).await
        {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.user_message())),
        },
        Err(msg) => (None, Some(msg)),
    };

    let content = backup_settings_content(report.as_ref(), error.as_deref());
    admin_response(
        &c,
        &user,
        "/integrations/backup",
        "Backup & Restore · Bunyip",
        content,
    )
}
