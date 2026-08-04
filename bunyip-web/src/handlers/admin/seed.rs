//! Admin panel: Seed data import / export (PSA-52).

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use maud::html;
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::handlers::{admin_guard, admin_response};
use crate::util::urlenc;
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon, success_box};
use crate::web::{redirect_cookies, AppState};

use super::with_attachment_hardening;

#[derive(Deserialize)]
pub struct SeedQuery {
    pub ok: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SeedImportForm {
    #[serde(default)]
    pub seed_json: String,
}

#[derive(Deserialize)]
pub struct SeedTemplateForm {
    #[serde(default)]
    pub template: String,
}

/// Admin data import/export page (PSA-52): download the current seed-owned data
/// as a canonical file, or paste one to load it. Import is enforced
/// non-production by the API; the note here sets that expectation.
pub async fn seed_data(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SeedQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::seed_templates(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let templates = data.unwrap_or_default();
    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Seed Data" } p class="mt-2 text-muted-foreground" { "Export the current demo data as a canonical file, or import one to populate this environment. Import is disabled in production." } }
            @if let Some(ok) = &q.ok { (success_box(ok)) }
            @if let Some(e) = &q.error { (error_box(e)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("layers", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Set up this environment" } }
                }
                div class="p-6 pt-0 space-y-4" {
                    p class="text-sm text-muted-foreground" { "Start empty and add your own data, or load a starter template below. Loading is idempotent and scoped to the reserved demo domain, so it only ever adds or refreshes demo rows." }
                    @if !reachable {
                        (error_box("Could not reach the API to load seed templates."))
                    } @else if templates.is_empty() {
                        p class="text-sm text-muted-foreground" { "No starter templates are available." }
                    } @else {
                        div class="grid gap-4 md:grid-cols-2" {
                            @for t in &templates {
                                div class="rounded-md border p-4 flex flex-col gap-2" {
                                    div { h4 class="font-semibold" { (t.name) } p class="text-sm text-muted-foreground" { (t.description) } }
                                    p class="text-xs text-muted-foreground" { (format!("{} users · {} apps · {} groups · {} feedback", t.users, t.applications, t.groups, t.feedback)) }
                                    form method="post" action="/admin/seed/template" class="mt-auto" {
                                        input type="hidden" name="template" value=(t.name);
                                        button type="submit" class=(button_class("default", "sm", "")) { (icon("download", "mr-2 h-4 w-4")) "Load " (t.name) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // BUNYIP-435: Export and Import flow into the two-column block grid
            // (top-aligned, one column below lg) instead of two sparse
            // full-width cards stacked vertically.
            (admin_block_grid(vec![
                admin_block("Export", None, html! {
                    p class="text-sm text-muted-foreground mb-4" { "Download the demo-domain users, feedback, and the full application catalog as a canonical seed JSON file. Passwords are never exported; re-imported accounts use the file's default password." }
                    a href="/admin/seed/export" class=(button_class("default", "default", "")) { (icon("download", "mr-2 h-4 w-4")) "Download seed export" }
                }),
                admin_block("Import", None, html! {
                    p class="text-sm text-muted-foreground mb-4" { "Paste a canonical seed JSON file. The import is idempotent and scoped to the reserved demo domain, so it only ever adds or refreshes seed rows." }
                    form method="post" action="/admin/seed/import" class="space-y-4" {
                        textarea name="seed_json" rows="12" required placeholder="{ \"version\": 1, ... }" class="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" {}
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Import seed data" }
                    }
                }),
            ]))
        }
    };
    admin_response(&c, &user, "/admin/seed", "Seed Data · Bunyip", content)
}

/// Stream the API's seed export straight to the browser as a file download
/// (mirrors `feedback_export`). Admin-gated; the API redacts secrets.
pub async fn seed_export(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/admin/seed/export", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"seed-export.json\"".to_string());
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/admin/seed", &c.set_cookies))
        }
        _ => redirect_cookies(
            &format!(
                "/admin/seed?error={}",
                urlenc("Could not export seed data.")
            ),
            &c.set_cookies,
        ),
    }
}

/// Handle the paste-and-import form: validate the text is JSON, forward it to
/// the API loader, and report the section counts (or the error) back on the
/// page.
pub async fn seed_import(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SeedImportForm>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let value: serde_json::Value = match serde_json::from_str(&f.seed_json) {
        Ok(v) => v,
        Err(e) => {
            return redirect_cookies(
                &format!(
                    "/admin/seed?error={}",
                    urlenc(&format!("That is not valid JSON: {e}"))
                ),
                &c.set_cookies,
            );
        }
    };
    match admin_api::import_seed(&st.api, c.forward.as_deref(), value).await {
        Ok(s) => redirect_cookies(
            &format!(
                "/admin/seed?ok={}",
                urlenc(&format!(
                    "Imported {} users, {} apps, {} groups, {} entitlements, {} feedback.",
                    s.users, s.applications, s.groups, s.entitlements, s.feedback
                ))
            ),
            &c.set_cookies,
        ),
        Err(e) => redirect_cookies(
            &format!("/admin/seed?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// Load a named starter template (PSA-57): forward the selected name to the API
/// loader and report the section counts (or the error) back on the page.
pub async fn seed_load_template(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SeedTemplateForm>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = f.template.trim();
    if name.is_empty() {
        return redirect_cookies(
            &format!("/admin/seed?error={}", urlenc("No template selected.")),
            &c.set_cookies,
        );
    }
    match admin_api::import_seed_template(&st.api, c.forward.as_deref(), name).await {
        Ok(s) => redirect_cookies(
            &format!(
                "/admin/seed?ok={}",
                urlenc(&format!(
                    "Loaded template '{name}': {} users, {} apps, {} groups, {} entitlements, {} feedback.",
                    s.users, s.applications, s.groups, s.entitlements, s.feedback
                ))
            ),
            &c.set_cookies,
        ),
        Err(e) => redirect_cookies(
            &format!("/admin/seed?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}
