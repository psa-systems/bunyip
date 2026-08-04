//! Admin panel: Applications.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::AdminApplication;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::urlenc;
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{badge, button_class, error_box, icon, toggle_switch};
use crate::web::{redirect_cookies, status_cookies, AppState};

use super::application_groups::group_assignment_form;

/// One row of the admin Applications list (BUNYIP-473).
///
/// `data-reorder-item` + `data-app-id` mark the row for the reorder script, and
/// `draggable` makes it a native drag source; the script only starts a drag from
/// the `data-reorder-handle` button, so the toggles and Edit link stay clickable.
/// The single grip handle replaces the old stacked up/down chevrons: it is a real
/// `<button>`, so it is keyboard-focusable and the script moves the row on
/// ArrowUp/ArrowDown. `cursor-grab` + the grip icon are the drag affordance.
pub(super) fn app_admin_row(app: &AdminApplication) -> Markup {
    html! {
        div class="py-3 flex items-center justify-between gap-4" data-reorder-item data-app-id=(app.id) draggable="true" {
            div class="flex items-center gap-3" {
                button type="button" data-reorder-handle
                    class="cursor-grab touch-none rounded p-1 text-muted-foreground hover:text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                    aria-label=(format!("Reorder {}. Drag, or focus this handle and use the up and down arrow keys.", app.display_name)) {
                    (icon("grip-vertical", "h-5 w-5"))
                }
                div class="space-y-1" {
                    p class="font-medium" { (app.display_name) }
                    p class="text-xs text-muted-foreground" { (app.slug) }
                    (surface_tags(&SurfaceVisibility::of(app)))
                }
            }
            div class="flex items-center gap-6" {
                // BUNYIP-420: toggle switches (color + knob position convey state,
                // single click applies). Each switch is its form's submit control,
                // posting the flipped value through the /field path.
                form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                    input type="hidden" name="field" value="is_active";
                    input type="hidden" name="value" value=(if app.is_active { "false" } else { "true" });
                    label class="text-sm text-muted-foreground" { "Active" }
                    (toggle_switch(app.is_active, "Toggle active"))
                }
                form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                    input type="hidden" name="field" value="maintenance_mode";
                    input type="hidden" name="value" value=(if app.maintenance_mode { "false" } else { "true" });
                    label class="text-sm text-muted-foreground" { "Maintenance" }
                    (toggle_switch(app.maintenance_mode, "Toggle maintenance mode"))
                }
                a href=(format!("/admin/applications/{}/edit", app.id)) class=(button_class("outline", "sm", "")) { "Edit" }
            }
        }
    }
}

pub async fn applications(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::applications(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let apps = data.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div class="flex items-center justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Applications" } p class="mt-2 text-muted-foreground" { "Configure available applications." } }
                a href="/admin/applications/new" class=(button_class("default", "default", "")) { "New application" }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Applications" } }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load applications."))
                    } @else if apps.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No applications" }
                    } @else {
                        // BUNYIP-473: drag-and-drop reorder. `data-reorder-list`
                        // + `data-reorder-action` are read by assets/js/app-reorder.js,
                        // which moves rows on drag (or ArrowUp/ArrowDown on a focused
                        // handle) and POSTs the new id order to the action.
                        div class="divide-y" data-reorder-list data-reorder-action="/admin/applications/reorder" {
                            @for app in apps.iter() { (app_admin_row(app)) }
                        }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Applications · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct AppFieldForm {
    pub field: String,
    pub value: String,
}
pub async fn application_field(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<AppFieldForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let val = f.value == "true";
    let mut map = serde_json::Map::new();
    map.insert(f.field.clone(), json!(val));
    let body = serde_json::Value::Object(map);
    let target = match admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await
    {
        Ok(_) => "/admin/applications".to_string(),
        Err(e) => {
            tracing::warn!(app_id = %id, field = %f.field, error = ?e, "admin update application failed");
            format!(
                "/admin/applications?toast_err={}",
                urlenc("Could not update application")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

// --- application distribution edit / create --------------------------------

/// Current values of the distribution form, borrowed for rendering. Shared by
/// the create and edit forms so the field layout cannot drift between them.
pub(super) struct DistView<'a> {
    pub(super) artifact_source: &'a str,
    pub(super) forgejo_owner: &'a str,
    pub(super) forgejo_repo: &'a str,
    pub(super) forgejo_package: &'a str,
    pub(super) pinned_release_tag: &'a str,
    pub(super) oci_image_owner: &'a str,
    pub(super) oci_image_name: &'a str,
    pub(super) pinned_image_tag: &'a str,
}

/// Identity fields shown only on the create form (the backend requires them;
/// they are immutable afterwards, so the edit form omits them).
pub(super) struct IdentityView<'a> {
    pub(super) name: &'a str,
    pub(super) slug: &'a str,
    pub(super) display_name: &'a str,
    pub(super) container_name: &'a str,
}

/// The descriptive / metadata fields the API accepts on both create and update
/// (`UpdateApplication` / `CreateApplication`): everything other than identity
/// and the distribution coordinates. Shared by the create and edit forms so the
/// field layout cannot drift between them. Borrowed for rendering.
pub(super) struct DetailsView<'a> {
    pub(super) description: &'a str,
    pub(super) icon_url: &'a str,
    pub(super) subdomain: &'a str,
    pub(super) version: &'a str,
    pub(super) source_code_url: &'a str,
    pub(super) release_notes_url: &'a str,
    pub(super) maintenance_message: &'a str,
}

/// An HTML checkbox submits its value only when checked, so an unchecked box is
/// absent from the form body (serde default `""`). Treat the standard checked
/// markers as true.
fn checkbox_on(s: &str) -> bool {
    s == "true" || s == "on"
}

fn details_fields(v: &DetailsView) -> Markup {
    html! {
        div class="space-y-2" { label class="text-sm font-medium" { "Description" } input name="description" value=(v.description) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Icon URL" } input name="icon_url" value=(v.icon_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Subdomain" } input name="subdomain" value=(v.subdomain) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Version" } input name="version" value=(v.version) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Source code URL" } input name="source_code_url" value=(v.source_code_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Release notes URL" } p class="text-xs text-muted-foreground" { "Linked from the applications view so users can see what changed (e.g. the Forgejo releases page)." } input name="release_notes_url" value=(v.release_notes_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Maintenance message" } p class="text-xs text-muted-foreground" { "Shown to users while maintenance mode is on." } input name="maintenance_message" value=(v.maintenance_message) class=(dashboard_input()); }
    }
}

fn distribution_fields(v: &DistView) -> Markup {
    html! {
        // BUNYIP-460: subsection subheads (smaller, muted, uppercase) so
        // "Binary (Forgejo)" / "Container (OCI)" read as nested groups under the
        // "Distribution" card title instead of competing with it.
        h4 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground" { "Binary (Forgejo)" }
        div class="space-y-2" {
            label class="text-sm font-medium" { "Artifact source" }
            select name="artifact_source" class=(dashboard_input()) {
                option value="release" selected[v.artifact_source != "generic_package"] { "release" }
                option value="generic_package" selected[v.artifact_source == "generic_package"] { "generic_package" }
            }
        }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo owner" } input name="forgejo_owner" value=(v.forgejo_owner) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo repo" } input name="forgejo_repo" value=(v.forgejo_repo) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo package" } p class="text-xs text-muted-foreground" { "generic_package sources only; leave blank to clear back to the repo name." } input name="forgejo_package" value=(v.forgejo_package) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Pinned release tag" } input name="pinned_release_tag" value=(v.pinned_release_tag) class=(dashboard_input()); }
        h4 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground border-t pt-4 mt-2" { "Container (OCI)" }
        div class="space-y-2" { label class="text-sm font-medium" { "OCI image owner" } input name="oci_image_owner" value=(v.oci_image_owner) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "OCI image name" } input name="oci_image_name" value=(v.oci_image_name) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Pinned image tag" } input name="pinned_image_tag" value=(v.pinned_image_tag) class=(dashboard_input()); }
    }
}

/// At-a-glance visibility of an application across the three distribution
/// surfaces shown in the admin UI. Each field MIRRORS the canonical predicate
/// in `bunyip-domain` (`crates/bunyip-domain/src/models/application.rs`) so the
/// badges cannot silently disagree with what users actually see; if a domain
/// rule changes, update it here too:
/// - `hub`: the user Applications section / hub launch tile, listed by
///   `ApplicationRepository::list_active_hosted` (`is_active && is_hosted`).
/// - `binary`: `Application::is_downloadable` / `download_source` (forgejo_owner
///   + pinned_release_tag + repo-or-package depending on `artifact_source`).
/// - `oci`: `Application::is_pullable` (is_active + all three OCI fields set).
///
/// `None` and empty/whitespace string fields are both treated as absent.
pub(super) struct SurfaceVisibility {
    hub: bool,
    binary: bool,
    oci: bool,
}

impl SurfaceVisibility {
    fn of(app: &AdminApplication) -> Self {
        fn present(field: &Option<String>) -> bool {
            field.as_deref().is_some_and(|s| !s.trim().is_empty())
        }
        // Mirrors `Application::download_source`: the `generic_package` source
        // accepts a package name or falls back to the repo; every other source
        // (including the `release` default) requires the repo.
        let binary = present(&app.forgejo_owner)
            && present(&app.pinned_release_tag)
            && if app.artifact_source.as_deref() == Some("generic_package") {
                present(&app.forgejo_package) || present(&app.forgejo_repo)
            } else {
                present(&app.forgejo_repo)
            };
        let oci = app.is_active
            && present(&app.oci_image_owner)
            && present(&app.oci_image_name)
            && present(&app.pinned_image_tag);
        Self {
            hub: app.is_active && app.is_hosted,
            binary,
            oci,
        }
    }
}

/// One surface badge: a colored `on_variant` when the app reaches the surface,
/// a muted outline `off_label` ("No X") when it does not.
fn surface_badge(on: bool, on_variant: &str, on_label: &str, off_label: &str) -> Markup {
    if on {
        badge(on_variant, on_label)
    } else {
        badge("outline", off_label)
    }
}

/// The Hub / Binary / OCI surface badges for one application. Rendered on the
/// admin Applications list and the edit page so an admin can see at a glance
/// which surfaces an app is (and is not) served in.
fn surface_tags(s: &SurfaceVisibility) -> Markup {
    html! {
        div class="flex flex-wrap items-center gap-1.5" {
            (surface_badge(s.hub, "success", "Hub", "No Hub"))
            (surface_badge(s.binary, "secondary", "Binary", "No Binary"))
            (surface_badge(s.oci, "secondary", "OCI", "No OCI"))
        }
    }
}

/// Render the application create/edit form. `identity` is `Some` only for
/// create (the edit form posts distribution fields only). `surfaces` is `Some`
/// only on the edit page of a persisted app, where the Hub/Binary/OCI badges
/// can be derived; create and error re-renders pass `None`. `error` renders a
/// banner and the form keeps the submitted values for correction.
pub(super) fn application_form(
    action: &str,
    heading: &str,
    blurb: &str,
    identity: Option<&IdentityView>,
    is_hosted: bool,
    details: &DetailsView,
    v: &DistView,
    surfaces: Option<&SurfaceVisibility>,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { (heading) }
                p class="mt-2 text-muted-foreground" { (blurb) }
                @if let Some(s) = surfaces { div class="mt-3" { (surface_tags(s)) } }
            }
            // BUNYIP-435: the same two-column block layout as Email/Tier
            // Settings. Details and Distribution sit side by side (one column
            // below lg) inside one form, so a single Save persists everything.
            // On create the Identity fields lead as a full-width block (they
            // are absent when editing).
            form method="post" action=(action) class="space-y-6" {
                @if let Some(err) = error { (error_box(err)) }
                @if let Some(id) = identity {
                    (admin_block("Identity", None, html! {
                        div class="space-y-4" {
                            div class="space-y-2" { label class="text-sm font-medium" { "Name" } input name="name" value=(id.name) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Slug" } input name="slug" value=(id.slug) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Display name" } input name="display_name" value=(id.display_name) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Container name" } input name="container_name" value=(id.container_name) required class=(dashboard_input()); }
                        }
                    }))
                }
                (admin_block_grid(vec![
                    admin_block("Details", None, html! {
                        div class="space-y-4" {
                            div class="flex items-start gap-2" {
                                input type="checkbox" name="is_hosted" value="true" checked[is_hosted] id="is_hosted" class="mt-1";
                                label for="is_hosted" class="text-sm font-medium" { "Hosted app" p class="text-xs font-normal text-muted-foreground" { "Checked: shows as a launchable hub tile. Unchecked: catalog-only distribution product (downloads / OCI pulls only)." } }
                            }
                            (details_fields(details))
                        }
                    }),
                    admin_block("Distribution", None, html! {
                        div class="space-y-4" { (distribution_fields(v)) }
                    }),
                ]))
                // BUNYIP-460: a full-width bordered footer under the grid so the
                // primary actions clearly terminate (and belong to) the whole
                // Details + Distribution form, not the separate Group card below.
                div class="flex items-center gap-2 border-t pt-6" {
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save application" }
                    a href="/admin/applications" class=(button_class("outline", "default", "")) { "Cancel" }
                }
            }
        }
    }
}

fn dist_view_from_form(f: &DistributionForm) -> DistView<'_> {
    DistView {
        artifact_source: &f.artifact_source,
        forgejo_owner: &f.forgejo_owner,
        forgejo_repo: &f.forgejo_repo,
        forgejo_package: &f.forgejo_package,
        pinned_release_tag: &f.pinned_release_tag,
        oci_image_owner: &f.oci_image_owner,
        oci_image_name: &f.oci_image_name,
        pinned_image_tag: &f.pinned_image_tag,
    }
}

fn details_view_from_dist_form(f: &DistributionForm) -> DetailsView<'_> {
    DetailsView {
        description: &f.description,
        icon_url: &f.icon_url,
        subdomain: &f.subdomain,
        version: &f.version,
        source_code_url: &f.source_code_url,
        release_notes_url: &f.release_notes_url,
        maintenance_message: &f.maintenance_message,
    }
}

/// Add every non-empty descriptive field (`DetailsView` columns) to an update /
/// create body, trimmed. Empty inputs are omitted so the backend keeps the
/// existing column (its UPDATE COALESCEs a NULL to the old value), matching the
/// "blank fields keep their current value" contract of the distribution fields.
fn insert_detail_fields(
    m: &mut serde_json::Map<String, serde_json::Value>,
    description: &str,
    icon_url: &str,
    subdomain: &str,
    version: &str,
    source_code_url: &str,
    release_notes_url: &str,
    maintenance_message: &str,
) {
    for (k, val) in [
        ("description", description),
        ("icon_url", icon_url),
        ("subdomain", subdomain),
        ("version", version),
        ("source_code_url", source_code_url),
        ("release_notes_url", release_notes_url),
        ("maintenance_message", maintenance_message),
    ] {
        if !val.trim().is_empty() {
            m.insert(k.into(), json!(val.trim()));
        }
    }
}

/// Body for PUT /admin/applications/{id}: set every non-empty distribution
/// field. Empty inputs are omitted so the backend keeps the existing column
/// (its UPDATE COALESCEs a NULL to the old value), EXCEPT `forgejo_package`,
/// which is always sent so an empty value clears it to NULL (the documented
/// backend sentinel). `forgejo_package` is also forced empty on non-generic
/// sources: it is meaningless there, and re-sending a prefilled package while
/// the admin flips the source to `release` would fail backend validation.
/// `is_hosted` is always sent so the checkbox can toggle it in both directions.
pub(super) fn distribution_update_body(f: &DistributionForm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !f.artifact_source.trim().is_empty() {
        m.insert("artifact_source".into(), json!(f.artifact_source.trim()));
    }
    for (k, val) in [
        ("forgejo_owner", &f.forgejo_owner),
        ("forgejo_repo", &f.forgejo_repo),
        ("pinned_release_tag", &f.pinned_release_tag),
        ("oci_image_owner", &f.oci_image_owner),
        ("oci_image_name", &f.oci_image_name),
        ("pinned_image_tag", &f.pinned_image_tag),
    ] {
        if !val.trim().is_empty() {
            m.insert(k.into(), json!(val.trim()));
        }
    }
    let package = if f.artifact_source.trim() == "generic_package" {
        f.forgejo_package.trim()
    } else {
        ""
    };
    m.insert("forgejo_package".into(), json!(package));
    m.insert("is_hosted".into(), json!(checkbox_on(&f.is_hosted)));
    insert_detail_fields(
        &mut m,
        &f.description,
        &f.icon_url,
        &f.subdomain,
        &f.version,
        &f.source_code_url,
        &f.release_notes_url,
        &f.maintenance_message,
    );
    serde_json::Value::Object(m)
}

#[derive(Deserialize, Default)]
pub struct DistributionForm {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub source_code_url: String,
    #[serde(default)]
    pub release_notes_url: String,
    #[serde(default)]
    pub maintenance_message: String,
    #[serde(default)]
    pub artifact_source: String,
    #[serde(default)]
    pub forgejo_owner: String,
    #[serde(default)]
    pub forgejo_repo: String,
    #[serde(default)]
    pub forgejo_package: String,
    #[serde(default)]
    pub pinned_release_tag: String,
    #[serde(default)]
    pub oci_image_owner: String,
    #[serde(default)]
    pub oci_image_name: String,
    #[serde(default)]
    pub pinned_image_tag: String,
    #[serde(default)]
    pub is_hosted: String,
}

/// GET /admin/applications/{id}/edit
/// Query params on the edit page. `error` is set when a delete attempt bounces
/// back (bad password / 2FA code) so the danger zone can show why.
#[derive(Deserialize)]
pub struct AppEditQuery {
    pub error: Option<String>,
}

pub async fn application_edit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<AppEditQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Distinguish a failed list fetch (network / auth / 5xx) from a genuinely
    // missing application; collapsing both to "not found" would mislead.
    let apps = match admin_api::applications(&st.api, c.forward.as_deref()).await {
        Ok(apps) => apps,
        Err(e) => {
            let content = html! {
                div class="space-y-6" {
                    h1 class="text-3xl font-bold" { "Edit application" }
                    (error_box(&e.user_message()))
                }
            };
            return admin_response(
                &c,
                &user,
                "/admin/applications",
                "Edit application · Bunyip",
                content,
            );
        }
    };
    // Groups for the assignment selector. A failed fetch degrades to no groups
    // (the selector still offers "Ungrouped") rather than blocking the edit.
    let groups = admin_api::application_groups(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let content = match apps.iter().find(|a| a.id == id) {
        None => {
            html! { div class="space-y-6" { h1 class="text-3xl font-bold" { "Edit application" } p class="text-muted-foreground" { "Application not found." } } }
        }
        Some(app) => {
            let v = DistView {
                artifact_source: app.artifact_source.as_deref().unwrap_or("release"),
                forgejo_owner: app.forgejo_owner.as_deref().unwrap_or_default(),
                forgejo_repo: app.forgejo_repo.as_deref().unwrap_or_default(),
                forgejo_package: app.forgejo_package.as_deref().unwrap_or_default(),
                pinned_release_tag: app.pinned_release_tag.as_deref().unwrap_or_default(),
                oci_image_owner: app.oci_image_owner.as_deref().unwrap_or_default(),
                oci_image_name: app.oci_image_name.as_deref().unwrap_or_default(),
                pinned_image_tag: app.pinned_image_tag.as_deref().unwrap_or_default(),
            };
            let details = DetailsView {
                description: app.description.as_deref().unwrap_or_default(),
                icon_url: app.icon_url.as_deref().unwrap_or_default(),
                subdomain: app.subdomain.as_deref().unwrap_or_default(),
                version: app.version.as_deref().unwrap_or_default(),
                source_code_url: app.source_code_url.as_deref().unwrap_or_default(),
                release_notes_url: app.release_notes_url.as_deref().unwrap_or_default(),
                maintenance_message: app.maintenance_message.as_deref().unwrap_or_default(),
            };
            let surfaces = SurfaceVisibility::of(app);
            html! {
                div class="mb-4" {
                    a class=(button_class("outline", "sm", "")) href=(format!("/admin/applications/{id}/docs")) { "Manage documentation" }
                }
                (application_form(
                    &format!("/admin/applications/{id}/distribution"),
                    &format!("Edit {}", app.display_name),
                    "Edit the application details, Forgejo binary, and OCI container coordinates. Blank fields keep their current value.",
                    None,
                    app.is_hosted,
                    &details,
                    &v,
                    Some(&surfaces),
                    None,
                ))
                // BUNYIP-460: match the Danger Zone's `mt-8` so the trailing
                // full-width sections keep one consistent vertical rhythm below
                // the form.
                div class="mt-8" { (group_assignment_form(&id, app.group_id.as_deref(), &groups)) }
                (app_danger_zone(&id, q.error.as_deref()))
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Edit application · Bunyip",
        content,
    )
}

/// Danger zone on the edit page: hard-delete the application. Mirrors the
/// account self-delete UI; the API requires the admin's password + 2FA code, so
/// both fields are collected and posted to the delete handler.
fn app_danger_zone(id: &str, error: Option<&str>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-destructive/30 mt-8" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight text-destructive-text flex items-center gap-2" { (icon("alert-triangle", "h-5 w-5")) "Danger Zone" }
                p class="text-sm text-muted-foreground" { "Permanently delete this application. Its entitlements, price links, and download caches are removed with it. This cannot be undone." }
            }
            div class="p-6 pt-0" {
                @if let Some(e) = error { (error_box(e)) }
                form method="post" action=(format!("/admin/applications/{id}/delete")) class="space-y-3 max-w-md mt-2" data-confirm="Permanently delete this application? This cannot be undone." {
                    div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" placeholder="Enter your password to confirm" class=(dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" placeholder="6-digit code" class=(dashboard_input()); }
                    button type="submit" class=(button_class("destructive", "default", "")) { (icon("trash", "mr-2 h-4 w-4")) "Delete application" }
                }
            }
        }
    }
}

/// POST /admin/applications/{id}/distribution
pub async fn application_distribution_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DistributionForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = distribution_update_body(&f);
    match admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await {
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        Err(e) => {
            let v = dist_view_from_form(&f);
            let details = details_view_from_dist_form(&f);
            let content = application_form(
                &format!("/admin/applications/{id}/distribution"),
                "Edit application",
                "Edit the application details, Forgejo binary, and OCI container coordinates. Blank fields keep their current value.",
                None,
                checkbox_on(&f.is_hosted),
                &details,
                &v,
                None,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/applications",
                "Edit application · Bunyip",
                content,
            )
        }
    }
}

#[derive(Deserialize)]
pub struct ReorderForm {
    #[serde(default)]
    pub ordered_ids: Vec<String>,
}

/// POST /admin/applications/reorder
/// Persist a new application display order from the drag-and-drop / keyboard
/// reorder control (BUNYIP-473). Called by `fetch`, so it returns a bare status
/// rather than a redirect: the page has already moved the rows, and a redirect
/// would reload the list at the top - the "jump" this ticket removes. A failed
/// upstream call surfaces as a non-2xx the client turns into a toast + reload.
pub async fn application_reorder(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::Json(f): axum::Json<ReorderForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match admin_api::reorder_applications(&st.api, c.forward.as_deref(), &f.ordered_ids).await {
        Ok(()) => status_cookies(StatusCode::NO_CONTENT, &c.set_cookies),
        Err(_) => status_cookies(StatusCode::BAD_GATEWAY, &c.set_cookies),
    }
}

#[derive(Deserialize)]
pub struct DeleteAppForm {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
}

/// POST /admin/applications/{id}/delete
pub async fn application_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DeleteAppForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match admin_api::delete_application(
        &st.api,
        c.forward.as_deref(),
        &id,
        &f.password,
        &f.totp_code,
    )
    .await
    {
        // Relay any cookie the guard rotated on both paths (mirrors user_delete);
        // a plain redirect would drop a refreshed session.
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        // Bad password / 2FA code (or any failure): bounce back to this app's
        // danger zone with the API's message rather than dropping the admin on a
        // blank page.
        Err(e) => redirect_cookies(
            &format!(
                "/admin/applications/{id}/edit?error={}",
                urlenc(&e.user_message())
            ),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize, Default)]
pub struct CreateAppForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub container_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub source_code_url: String,
    #[serde(default)]
    pub release_notes_url: String,
    #[serde(default)]
    pub maintenance_message: String,
    #[serde(default)]
    pub artifact_source: String,
    #[serde(default)]
    pub forgejo_owner: String,
    #[serde(default)]
    pub forgejo_repo: String,
    #[serde(default)]
    pub forgejo_package: String,
    #[serde(default)]
    pub pinned_release_tag: String,
    #[serde(default)]
    pub oci_image_owner: String,
    #[serde(default)]
    pub oci_image_name: String,
    #[serde(default)]
    pub pinned_image_tag: String,
    #[serde(default)]
    pub is_hosted: String,
}

/// Body for POST /admin/applications: required identity fields plus every
/// non-empty distribution field. Empty distribution inputs are omitted (a new
/// row has nothing to clear, and an empty string would fail backend
/// validation). `forgejo_package` is only sent on a `generic_package` source
/// (it is invalid on `release`). `is_hosted` reflects the checkbox so a
/// catalog-only product (unchecked) is not forced to the DB default of hosted.
pub(super) fn create_app_body(f: &CreateAppForm) -> Result<serde_json::Value, String> {
    use crate::handlers::validate;
    // BUNYIP-112: identity fields are bounded + slug-checked at the edge.
    // `slug` is load-bearing for OCI repo paths in
    // `Application::oci_pull_image`, so an unconstrained value would
    // silently end up in pull URLs.
    let name = validate::trim_bounded(&f.name, "Name", 200)?;
    let slug = validate::slug(&f.slug, "Slug")?;
    let display_name = validate::trim_bounded(&f.display_name, "Display name", 200)?;
    let container_name = validate::trim_bounded(&f.container_name, "Container name", 200)?;
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(name));
    m.insert("slug".into(), json!(slug));
    m.insert("display_name".into(), json!(display_name));
    m.insert("container_name".into(), json!(container_name));
    m.insert("is_hosted".into(), json!(checkbox_on(&f.is_hosted)));
    insert_detail_fields(
        &mut m,
        &f.description,
        &f.icon_url,
        &f.subdomain,
        &f.version,
        &f.source_code_url,
        &f.release_notes_url,
        &f.maintenance_message,
    );
    if !f.artifact_source.trim().is_empty() {
        m.insert("artifact_source".into(), json!(f.artifact_source.trim()));
    }
    for (k, val) in [
        ("forgejo_owner", &f.forgejo_owner),
        ("forgejo_repo", &f.forgejo_repo),
        ("pinned_release_tag", &f.pinned_release_tag),
        ("oci_image_owner", &f.oci_image_owner),
        ("oci_image_name", &f.oci_image_name),
        ("pinned_image_tag", &f.pinned_image_tag),
    ] {
        if let Some(v) = validate::trim_bounded_opt(val, k, 200)? {
            m.insert(k.into(), json!(v));
        }
    }
    if f.artifact_source.trim() == "generic_package" && !f.forgejo_package.trim().is_empty() {
        let pkg = validate::trim_bounded(&f.forgejo_package, "forgejo_package", 200)?;
        m.insert("forgejo_package".into(), json!(pkg));
    }
    Ok(serde_json::Value::Object(m))
}

/// GET /admin/applications/new
pub async fn application_new(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let id = IdentityView {
        name: "",
        slug: "",
        display_name: "",
        container_name: "",
    };
    let details = DetailsView {
        description: "",
        icon_url: "",
        subdomain: "",
        version: "",
        source_code_url: "",
        release_notes_url: "",
        maintenance_message: "",
    };
    let v = DistView {
        artifact_source: "release",
        forgejo_owner: "",
        forgejo_repo: "",
        forgejo_package: "",
        pinned_release_tag: "",
        oci_image_owner: "",
        oci_image_name: "",
        pinned_image_tag: "",
    };
    let content = application_form(
        "/admin/applications",
        "New application",
        "Create a catalog application and (optionally) its Forgejo binary and OCI container coordinates.",
        Some(&id),
        true,
        &details,
        &v,
        None,
        None,
    );
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "New application · Bunyip",
        content,
    )
}

/// POST /admin/applications
pub async fn application_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateAppForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Render helper so the validation-error and API-error paths share the
    // identical reconstruction of the form view (BUNYIP-112).
    let render_form_error = |err: &str| -> Response {
        let id = IdentityView {
            name: &f.name,
            slug: &f.slug,
            display_name: &f.display_name,
            container_name: &f.container_name,
        };
        let v = DistView {
            artifact_source: &f.artifact_source,
            forgejo_owner: &f.forgejo_owner,
            forgejo_repo: &f.forgejo_repo,
            forgejo_package: &f.forgejo_package,
            pinned_release_tag: &f.pinned_release_tag,
            oci_image_owner: &f.oci_image_owner,
            oci_image_name: &f.oci_image_name,
            pinned_image_tag: &f.pinned_image_tag,
        };
        let details = DetailsView {
            description: &f.description,
            icon_url: &f.icon_url,
            subdomain: &f.subdomain,
            version: &f.version,
            source_code_url: &f.source_code_url,
            release_notes_url: &f.release_notes_url,
            maintenance_message: &f.maintenance_message,
        };
        let content = application_form(
            "/admin/applications",
            "New application",
            "Create a catalog application and (optionally) its Forgejo binary and OCI container coordinates.",
            Some(&id),
            checkbox_on(&f.is_hosted),
            &details,
            &v,
            None,
            Some(err),
        );
        admin_response(
            &c,
            &user,
            "/admin/applications",
            "New application · Bunyip",
            content,
        )
    };
    let body = match create_app_body(&f) {
        Ok(b) => b,
        Err(msg) => return render_form_error(&msg),
    };
    match admin_api::create_application(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        Err(e) => render_form_error(&e.user_message()),
    }
}

// --- application documentation (BUNYIP-388) ---------------------------------

/// Add/edit form fields for one documentation page.
#[derive(Debug, Deserialize)]
pub struct DocForm {
    pub slug: String,
    pub title: String,
    pub body: String,
    // Parsed with `validate::parse_i32` (empty -> 0, non-numeric -> handled),
    // not deserialized as i32, so a cleared number input does not 400 the form.
    #[serde(default)]
    pub sort_order: String,
}

/// GET /admin/applications/{id}/docs - manage an app's documentation pages.
pub async fn application_docs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let app_name = match admin_api::applications(&st.api, c.forward.as_deref()).await {
        Ok(apps) => apps
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.display_name.clone())
            .unwrap_or_else(|| id.clone()),
        Err(e) => {
            let content = html! {
                div class="space-y-6" {
                    h1 class="text-3xl font-bold" { "Manage documentation" }
                    (error_box(&e.user_message()))
                }
            };
            return admin_response(
                &c,
                &user,
                "/admin/applications",
                "Manage documentation · Bunyip",
                content,
            );
        }
    };
    let docs = admin_api::app_docs(&st.api, c.forward.as_deref(), &id)
        .await
        .unwrap_or_default();
    let content = html! {
        div class="space-y-6" {
            div {
                a class="text-sm text-muted-foreground hover:underline" href="/admin/applications" { "← Applications" }
                h1 class="text-3xl font-bold mt-2" { "Documentation: " (app_name) }
                p class="text-muted-foreground" { "Public pages, rendered as markdown (raw HTML is stripped). Lower sort order shows first." }
            }
            div class="space-y-6" {
                @if docs.is_empty() {
                    p class="text-muted-foreground" { "No pages yet. Add one below." }
                }
                @for d in &docs {
                    div class="rounded-lg border p-4 space-y-3" {
                        form method="post" action=(format!("/admin/applications/{id}/docs/{}", d.id)) class="space-y-3" {
                            div class="grid gap-3 md:grid-cols-3" {
                                label class="text-sm block" { "Title" input class="mt-1 w-full rounded border px-2 py-1" name="title" value=(d.title) required; }
                                label class="text-sm block" { "Slug" input class="mt-1 w-full rounded border px-2 py-1" name="slug" value=(d.slug) required; }
                                label class="text-sm block" { "Sort order" input type="number" class="mt-1 w-full rounded border px-2 py-1" name="sort_order" value=(d.sort_order); }
                            }
                            label class="text-sm block" { "Body (markdown)" textarea class="mt-1 w-full rounded border px-2 py-1 font-mono text-sm" name="body" rows="10" { (d.body) } }
                            button type="submit" class=(button_class("default", "sm", "")) { "Save" }
                        }
                        form method="post" action=(format!("/admin/applications/{id}/docs/{}/delete", d.id)) data-confirm="Delete this documentation entry? This cannot be undone." {
                            button type="submit" class=(button_class("destructive", "sm", "")) { "Delete" }
                        }
                    }
                }
            }
            div class="rounded-lg border p-4 space-y-3" {
                h2 class="text-xl font-semibold" { "Add a page" }
                form method="post" action=(format!("/admin/applications/{id}/docs")) class="space-y-3" {
                    div class="grid gap-3 md:grid-cols-3" {
                        label class="text-sm block" { "Title" input class="mt-1 w-full rounded border px-2 py-1" name="title" required; }
                        label class="text-sm block" { "Slug" input class="mt-1 w-full rounded border px-2 py-1" name="slug" placeholder="getting-started" required; }
                        label class="text-sm block" { "Sort order" input type="number" class="mt-1 w-full rounded border px-2 py-1" name="sort_order" value="0"; }
                    }
                    label class="text-sm block" { "Body (markdown)" textarea class="mt-1 w-full rounded border px-2 py-1 font-mono text-sm" name="body" rows="10" {} }
                    button type="submit" class=(button_class("default", "sm", "")) { "Add page" }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Manage documentation · Bunyip",
        content,
    )
}

/// POST /admin/applications/{id}/docs - create a page, then back to the manager.
pub async fn application_doc_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DocForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sort_order = crate::handlers::validate::parse_i32(&f.sort_order, "Sort order").unwrap_or(0);
    let target = match admin_api::create_app_doc(
        &st.api,
        c.forward.as_deref(),
        &id,
        &f.slug,
        &f.title,
        &f.body,
        sort_order,
    )
    .await
    {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, slug = %f.slug, error = ?e, "admin create app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not create documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/applications/{id}/docs/{doc_id} - update a page.
pub async fn application_doc_update(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, doc_id)): Path<(String, String)>,
    Form(f): Form<DocForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sort_order = crate::handlers::validate::parse_i32(&f.sort_order, "Sort order").unwrap_or(0);
    let target = match admin_api::update_app_doc(
        &st.api,
        c.forward.as_deref(),
        &doc_id,
        &f.slug,
        &f.title,
        &f.body,
        sort_order,
    )
    .await
    {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, doc_id = %doc_id, error = ?e, "admin update app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not update documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/applications/{id}/docs/{doc_id}/delete - delete a page.
pub async fn application_doc_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, doc_id)): Path<(String, String)>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_app_doc(&st.api, c.forward.as_deref(), &doc_id).await {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, doc_id = %doc_id, error = ?e, "admin delete app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not delete documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}
