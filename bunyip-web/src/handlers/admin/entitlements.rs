//! Admin panel: Entitlements.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::html;
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::UserEntitlement;
use crate::handlers::{admin_guard, admin_response};
use crate::util::rel_time;
use crate::views::ui::{badge, button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

pub async fn entitlements(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::applications(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let apps = data.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Entitlements" } p class="mt-2 text-muted-foreground" { "Control which applications require a per-product entitlement to access." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Products" } p class="text-sm text-muted-foreground" { "Restricted products are only available to users who have been granted an entitlement." } }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load applications."))
                    } @else if apps.is_empty() {
                        div class="flex flex-col items-center justify-center py-12 text-center text-muted-foreground" {
                            (icon("package", "h-8 w-8 mb-2 opacity-50")) "No applications"
                        }
                    } @else {
                        // BUNYIP-415: flow product rows into two columns (one
                        // below lg) so the catalog uses the width.
                        div class="grid gap-x-8 lg:grid-cols-2" {
                            @for app in &apps {
                                div class="py-3 flex items-center justify-between gap-4 border-b last:border-0" {
                                    div {
                                        p class="font-medium flex items-center gap-2" { (app.display_name) @if app.requires_entitlement { (badge("default", "Restricted")) } }
                                        p class="text-xs text-muted-foreground" { (app.slug) }
                                    }
                                    form method="post" action=(format!("/admin/applications/{}/restricted-toggle", app.slug)) {
                                        input type="hidden" name="value" value=(if app.requires_entitlement { "false" } else { "true" });
                                        button type="submit" class=(button_class("outline", "sm", "")) { @if app.requires_entitlement { "Open" } @else { "Restrict" } }
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
        "/admin/entitlements",
        "Entitlements · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct RestrictedForm {
    pub value: String,
}
pub async fn set_app_restricted(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(f): Form<RestrictedForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let requires_entitlement = f.value == "true";
    let _ = admin_api::set_application_restricted(
        &st.api,
        c.forward.as_deref(),
        &slug,
        requires_entitlement,
    )
    .await;
    redirect_cookies("/admin/entitlements", &c.set_cookies)
}

pub async fn user_entitlements(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let granted_data = admin_api::list_user_entitlements(&st.api, fwd, &user_id).await;
    let granted_reachable = granted_data.is_ok();
    let granted: Vec<UserEntitlement> = granted_data.unwrap_or_default();
    let apps_data = admin_api::applications(&st.api, fwd).await;
    let apps_reachable = apps_data.is_ok();
    let apps = apps_data.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "User Entitlements" }
                p class="mt-2 text-muted-foreground" { "Grant or revoke per-product access for this user." }
                p class="mt-1 text-xs text-muted-foreground" { a href="/admin/users" class="text-primary hover:underline" { "Back to users" } }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Granted Entitlements" } }
                div class="p-6 pt-0" {
                    @if !granted_reachable {
                        (error_box("Could not reach the API to load entitlements."))
                    } @else if granted.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No entitlements granted" }
                    } @else {
                        div class="divide-y" {
                            @for e in &granted {
                                div class="flex items-center justify-between py-3" {
                                    div {
                                        p class="font-medium flex items-center gap-2" { (e.display_name) (badge("outline", &e.source)) }
                                        p class="text-xs text-muted-foreground" { (e.slug) " · granted " (rel_time(&e.granted_at)) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Products" } p class="text-sm text-muted-foreground" { "Grant or revoke any product for this user." } }
                div class="p-6 pt-0" {
                    @if !apps_reachable {
                        (error_box("Could not reach the API to load applications."))
                    } @else if apps.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No applications" }
                    } @else {
                        div class="divide-y" {
                            @for app in &apps {
                                @let has = granted.iter().any(|e| e.slug == app.slug);
                                div class="py-3 flex items-center justify-between gap-4" {
                                    div {
                                        p class="font-medium flex items-center gap-2" { (app.display_name) @if app.requires_entitlement { (badge("default", "Restricted")) } @if has { (badge("outline", "Granted")) } }
                                        p class="text-xs text-muted-foreground" { (app.slug) }
                                    }
                                    @if has {
                                        form method="post" action=(format!("/admin/users/{}/entitlements/revoke", user_id)) data-confirm=(format!("Revoke the {} entitlement from this user? They immediately lose access to it.", app.display_name)) {
                                            input type="hidden" name="slug" value=(app.slug);
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Revoke" }
                                        }
                                    } @else {
                                        form method="post" action=(format!("/admin/users/{}/entitlements/grant", user_id)) data-confirm=(format!("Grant the {} entitlement to this user?", app.display_name)) {
                                            input type="hidden" name="slug" value=(app.slug);
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Grant" }
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
        "/admin/users",
        "User Entitlements · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct SlugForm {
    pub slug: String,
}
pub async fn grant_user_entitlement_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(f): Form<SlugForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ =
        admin_api::grant_user_entitlement(&st.api, c.forward.as_deref(), &user_id, &f.slug).await;
    redirect_cookies(
        &format!("/admin/users/{user_id}/entitlements"),
        &c.set_cookies,
    )
}
pub async fn revoke_user_entitlement_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(f): Form<SlugForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ =
        admin_api::revoke_user_entitlement(&st.api, c.forward.as_deref(), &user_id, &f.slug).await;
    redirect_cookies(
        &format!("/admin/users/{user_id}/entitlements"),
        &c.set_cookies,
    )
}
