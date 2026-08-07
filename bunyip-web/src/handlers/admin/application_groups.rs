//! Admin panel: Application Groups (BUNYIP-100).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::ApplicationGroup;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::urlenc;
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, empty_state, error_box, icon};
use crate::web::{redirect_cookies, AppState};

#[derive(Deserialize, Default)]
pub struct GroupForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub sort_order: String,
}

/// JSON body for create/update of a group. Required identity fields are
/// bounded and slug-checked; description / icon_url collapse empty to null;
/// sort_order is parsed as a bounded `i32` so non-numeric and out-of-INTEGER
/// inputs surface as inline errors instead of silently becoming 0 or
/// truncating (BUNYIP-113). Name / slug / icon_url validation lands here as
/// part of the BUNYIP-112 sweep so create + edit share the same edge.
fn group_body(f: &GroupForm) -> Result<serde_json::Value, String> {
    use crate::handlers::validate;
    let name = validate::trim_bounded(&f.name, "Name", 200)?;
    let slug = validate::slug(&f.slug, "Slug")?;
    let display_name = validate::trim_bounded(&f.display_name, "Display name", 200)?;
    let description = validate::trim_bounded_opt(&f.description, "Description", 1000)?;
    let icon_url = validate::url_opt(&f.icon_url, "Icon URL", 512)?;
    let sort_order = validate::parse_i32(&f.sort_order, "Sort order")?;
    Ok(json!({
        "name": name,
        "slug": slug,
        "display_name": display_name,
        "description": description,
        "icon_url": icon_url,
        "sort_order": sort_order,
    }))
}

/// Shared create/edit form for a group.
pub(super) fn group_form(
    action: &str,
    heading: &str,
    g: Option<&ApplicationGroup>,
    error: Option<&str>,
) -> Markup {
    let name = g.map(|g| g.name.as_str()).unwrap_or_default();
    let slug = g.map(|g| g.slug.as_str()).unwrap_or_default();
    let display_name = g.map(|g| g.display_name.as_str()).unwrap_or_default();
    let description = g.and_then(|g| g.description.as_deref()).unwrap_or_default();
    let icon_url = g.and_then(|g| g.icon_url.as_deref()).unwrap_or_default();
    let sort_order = g.map(|g| g.sort_order).unwrap_or(0);
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { (heading) } p class="mt-2 text-muted-foreground" { "Group related applications under one heading on the Applications page." } }
            // BUNYIP-435: two-column block layout (Identity | Presentation),
            // matching Email/Pricing tiers, inside one form so a single Save
            // persists everything.
            form method="post" action=(action) class="space-y-6" {
                @if let Some(err) = error { (error_box(err)) }
                (admin_block_grid(vec![
                    admin_block("Identity", None, html! {
                        div class="space-y-4" {
                            div class="space-y-2" { label for="name" class="text-sm font-medium" { "Name" } input id="name" name="name" value=(name) required class=(dashboard_input()); }
                            div class="space-y-2" { label for="slug" class="text-sm font-medium" { "Slug" } input id="slug" name="slug" value=(slug) required class=(dashboard_input()); }
                            div class="space-y-2" { label for="display_name" class="text-sm font-medium" { "Display name" } input id="display_name" name="display_name" value=(display_name) required class=(dashboard_input()); }
                        }
                    }),
                    admin_block("Presentation", None, html! {
                        div class="space-y-4" {
                            div class="space-y-2" { label for="description" class="text-sm font-medium" { "Description" } input id="description" name="description" value=(description) class=(dashboard_input()); }
                            div class="space-y-2" { label for="icon_url" class="text-sm font-medium" { "Icon URL" } input id="icon_url" name="icon_url" value=(icon_url) class=(dashboard_input()); }
                            div class="space-y-2" { label for="sort_order" class="text-sm font-medium" { "Sort order" } input id="sort_order" name="sort_order" type="number" value=(sort_order) class=(dashboard_input()); }
                        }
                    }),
                ]))
                div class="flex items-center gap-2 pt-2" {
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    a href="/admin/application-groups" class=(button_class("outline", "default", "")) { "Cancel" }
                }
            }
        }
    }
}

/// A group `<select>` + save button for the application edit page. Posts to the
/// dedicated set-group endpoint so it never collides with the distribution save
/// (which COALESCEs and cannot clear group_id).
pub(super) fn group_assignment_form(
    app_id: &str,
    current: Option<&str>,
    groups: &[ApplicationGroup],
) -> Markup {
    // BUNYIP-460: same card treatment (title scale + subtitle) as the Details /
    // Distribution / Danger Zone sections so "Group" reads as a peer section, and
    // its own "Save group" is unmistakably scoped to the group assignment rather
    // than the Details + Distribution form above.
    admin_block(
        "Group",
        Some("Assign this application to a group, or leave it ungrouped."),
        html! {
            form method="post" action=(format!("/admin/applications/{app_id}/group")) class="flex items-end gap-2 max-w-md" {
                select name="group_id" class=(dashboard_input()) {
                    option value="" selected[current.is_none()] { "Ungrouped" }
                    @for g in groups {
                        option value=(g.id) selected[current == Some(g.id.as_str())] { (g.display_name) }
                    }
                }
                button type="submit" class=(button_class("default", "default", "")) { "Save group" }
            }
        },
    )
}

/// GET /admin/application-groups
pub async fn application_groups(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::application_groups(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let groups = data.unwrap_or_default();
    let content = html! {
        div class="space-y-6" {
            div class="flex items-center justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Application Groups" } p class="mt-2 text-muted-foreground" { "Group related applications under one heading." } }
                a href="/admin/application-groups/new" class=(button_class("default", "default", "")) { "New group" }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load application groups."))
                    } @else if groups.is_empty() {
                        (empty_state("layers", "No groups yet", None))
                    } @else {
                        div class="divide-y" {
                            @for g in &groups {
                                div class="py-3 flex items-center justify-between gap-4" {
                                    div { p class="font-medium" { (g.display_name) } p class="text-xs text-muted-foreground" { (g.slug) } }
                                    div class="flex items-center gap-2" {
                                        a href=(format!("/admin/application-groups/{}/edit", g.id)) class=(button_class("outline", "sm", "")) { "Edit" }
                                        form method="post" action=(format!("/admin/application-groups/{}/delete", g.id)) data-confirm="Delete this application group? This cannot be undone." {
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Delete" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "Application Groups · Bunyip",
        content,
    )
}

/// GET /admin/application-groups/new
pub async fn application_group_new(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = group_form("/admin/application-groups", "New group", None, None);
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "New group · Bunyip",
        content,
    )
}

/// POST /admin/application-groups
pub async fn application_group_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<GroupForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = match group_body(&f) {
        Ok(b) => b,
        Err(msg) => {
            let content = group_form("/admin/application-groups", "New group", None, Some(&msg));
            return admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "New group · Bunyip",
                content,
            );
        }
    };
    match admin_api::create_application_group(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/application-groups", &c.set_cookies),
        Err(e) => {
            let content = group_form(
                "/admin/application-groups",
                "New group",
                None,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "New group · Bunyip",
                content,
            )
        }
    }
}

/// GET /admin/application-groups/{id}/edit
pub async fn application_group_edit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::application_groups(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let groups = data.unwrap_or_default();
    let content = match groups.iter().find(|g| g.id == id) {
        None => {
            html! { div class="space-y-6" { h1 class="text-3xl font-bold" { "Edit group" }
                @if !reachable {
                    (error_box("Could not reach the API to load application groups."))
                } @else {
                    p class="text-muted-foreground" { "Group not found." }
                }
            } }
        }
        Some(g) => group_form(
            &format!("/admin/application-groups/{id}"),
            &format!("Edit {}", g.display_name),
            Some(g),
            None,
        ),
    };
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "Edit group · Bunyip",
        content,
    )
}

/// POST /admin/application-groups/{id}
pub async fn application_group_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<GroupForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = match group_body(&f) {
        Ok(b) => b,
        Err(msg) => {
            let content = group_form(
                &format!("/admin/application-groups/{id}"),
                "Edit group",
                None,
                Some(&msg),
            );
            return admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "Edit group · Bunyip",
                content,
            );
        }
    };
    match admin_api::update_application_group(&st.api, c.forward.as_deref(), &id, body).await {
        Ok(()) => redirect_cookies("/admin/application-groups", &c.set_cookies),
        Err(e) => {
            let content = group_form(
                &format!("/admin/application-groups/{id}"),
                "Edit group",
                None,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "Edit group · Bunyip",
                content,
            )
        }
    }
}

/// POST /admin/application-groups/{id}/delete
pub async fn application_group_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_application_group(&st.api, c.forward.as_deref(), &id).await
    {
        Ok(_) => "/admin/application-groups".to_string(),
        Err(e) => {
            tracing::warn!(group_id = %id, error = ?e, "admin delete application group failed");
            format!(
                "/admin/application-groups?toast_err={}",
                urlenc("Could not delete application group")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct SetGroupForm {
    #[serde(default)]
    pub group_id: String,
}

/// POST /admin/applications/{id}/group
pub async fn application_set_group(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<SetGroupForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let group_id = if f.group_id.trim().is_empty() {
        None
    } else {
        Some(f.group_id.trim())
    };
    let _ = admin_api::set_application_group(&st.api, c.forward.as_deref(), &id, group_id).await;
    redirect_cookies(&format!("/admin/applications/{id}/edit"), &c.set_cookies)
}
