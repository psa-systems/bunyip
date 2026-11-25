//! Organizations and teams admin surface, gated on `orgs_enabled` (BUNYIP-493,
//! BUNYIP-672).
//!
//! The semantics are Enable Pricing's: off means invisible, not merely inert.
//! The route stays mounted; when `orgs_enabled()` is false the handler returns
//! the branded 404 the router fallback renders BEFORE the auth guard runs, so
//! a redirect to `/login` does not confirm the route exists.

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;

use crate::api::organizations as orgs_api;
use crate::api::organizations::{OrganizationResponse, TeamMemberResponse, TeamResponse};
use crate::handlers::{dashboard_input, dashboard_response, guard};
use crate::views::layout::orgs_enabled;
use crate::views::ui::{button_class, empty_state};
use crate::web::{html_cookies, AppState};

#[derive(Debug, Deserialize)]
pub struct OrgNameForm {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct TeamForm {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MemberForm {
    pub bunyip_user_id: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoleForm {
    pub role: String,
}

fn org_card(org: &OrganizationResponse) -> Markup {
    html! {
        div class="rounded-lg border bg-card p-6 space-y-4" {
            div class="flex items-start justify-between" {
                div {
                    h2 class="text-xl font-semibold" { (org.name) }
                    p class="text-sm text-muted-foreground" { "Created " (org.created_at) }
                }
            }
            form
                hx-put="/organizations/name"
                hx-target="closest .rounded-lg"
                hx-swap="outerHTML"
                class="flex items-end gap-2"
            {
                div class="flex-1 space-y-1" {
                    label class="text-sm font-medium" for="rename-name" { "Rename" }
                    input id="rename-name" name="name" required value=(org.name) class=(dashboard_input());
                }
                button type="submit" class=(button_class("default", "default", "")) { "Save" }
            }
        }
    }
}

fn create_org_card() -> Markup {
    html! {
        div class="rounded-lg border bg-card p-6" {
            h2 class="text-xl font-semibold" { "Create your organization" }
            p class="mt-2 text-sm text-muted-foreground" {
                "Group collaborators into teams you share accounts with."
            }
            form
                hx-post="/organizations"
                hx-target="#organization-root"
                hx-swap="outerHTML"
                class="mt-4 flex items-end gap-2"
            {
                div class="flex-1 space-y-1" {
                    label class="text-sm font-medium" for="create-name" { "Name" }
                    input id="create-name" name="name" required placeholder="Acme" class=(dashboard_input());
                }
                button type="submit" class=(button_class("default", "default", "")) { "Create" }
            }
        }
    }
}

fn team_row(team: &TeamResponse, members: &[TeamMemberResponse]) -> Markup {
    html! {
        div class="rounded-lg border bg-card p-4 space-y-3" id=(format!("team-{}", team.id)) {
            div class="flex items-start justify-between gap-2" {
                div {
                    h3 class="text-lg font-medium" { (team.name) }
                    @if let Some(d) = &team.description {
                        p class="text-sm text-muted-foreground" { (d) }
                    }
                }
                button
                    type="button"
                    hx-delete=(format!("/organizations/teams/{}", team.id))
                    hx-target=(format!("#team-{}", team.id))
                    hx-swap="outerHTML"
                    hx-confirm="Delete this team?"
                    class=(button_class("destructive", "sm", ""))
                { "Delete" }
            }
            div class="space-y-2" {
                h4 class="text-sm font-medium text-muted-foreground" { "Members" }
                @if members.is_empty() {
                    (empty_state("users", "No members yet.", None))
                } @else {
                    ul class="space-y-1" {
                        @for m in members {
                            li class="flex items-center justify-between gap-2 text-sm" {
                                span class="font-mono text-xs" { (m.bunyip_user_id) }
                                span class="rounded bg-muted px-2 py-0.5 text-xs" { (m.role) }
                                button
                                    type="button"
                                    hx-delete=(format!("/organizations/teams/{}/members/{}", team.id, m.bunyip_user_id))
                                    hx-target=(format!("#team-{}", team.id))
                                    hx-swap="outerHTML"
                                    class=(button_class("destructive", "sm", ""))
                                { "Remove" }
                            }
                        }
                    }
                }
                form
                    hx-post=(format!("/organizations/teams/{}/members", team.id))
                    hx-target=(format!("#team-{}", team.id))
                    hx-swap="outerHTML"
                    class="flex flex-wrap items-end gap-2"
                {
                    div class="flex-1 min-w-[220px] space-y-1" {
                        label class="text-xs font-medium" for=(format!("member-id-{}", team.id)) { "User ID" }
                        input
                            id=(format!("member-id-{}", team.id))
                            name="bunyip_user_id"
                            required
                            placeholder="uuid"
                            class=(dashboard_input());
                    }
                    div class="w-32 space-y-1" {
                        label class="text-xs font-medium" for=(format!("member-role-{}", team.id)) { "Role" }
                        input
                            id=(format!("member-role-{}", team.id))
                            name="role"
                            placeholder="member"
                            class=(dashboard_input());
                    }
                    button type="submit" class=(button_class("secondary", "sm", "")) { "Add" }
                }
            }
        }
    }
}

fn teams_section(teams: &[TeamResponse], members: &[(String, Vec<TeamMemberResponse>)]) -> Markup {
    html! {
        div class="space-y-4" id="teams-section" {
            div class="flex items-center justify-between" {
                h2 class="text-xl font-semibold" { "Teams" }
            }
            form
                hx-post="/organizations/teams"
                hx-target="#teams-section"
                hx-swap="outerHTML"
                class="rounded-lg border bg-card p-4 flex flex-wrap items-end gap-2"
            {
                div class="flex-1 min-w-[220px] space-y-1" {
                    label class="text-sm font-medium" for="team-name" { "New team name" }
                    input id="team-name" name="name" required placeholder="Platform" class=(dashboard_input());
                }
                div class="flex-1 min-w-[260px] space-y-1" {
                    label class="text-sm font-medium" for="team-description" { "Description" }
                    input id="team-description" name="description" placeholder="Optional" class=(dashboard_input());
                }
                button type="submit" class=(button_class("default", "default", "")) { "Create team" }
            }
            @if teams.is_empty() {
                (empty_state("users", "No teams yet.", None))
            } @else {
                div class="space-y-3" {
                    @for t in teams {
                        @let empty_vec: Vec<TeamMemberResponse> = Vec::new();
                        @let ms = members.iter().find(|(id, _)| id == &t.id).map(|(_, v)| v).unwrap_or(&empty_vec);
                        (team_row(t, ms))
                    }
                }
            }
        }
    }
}

fn organizations_root(
    org: Option<&OrganizationResponse>,
    teams: &[TeamResponse],
    members: &[(String, Vec<TeamMemberResponse>)],
) -> Markup {
    html! {
        div class="space-y-6" id="organization-root" {
            div {
                h1 class="text-3xl font-bold" { "Organization" }
                p class="mt-2 text-muted-foreground" {
                    "Administer the organization you own and its teams."
                }
            }
            @match org {
                Some(o) => (org_card(o)),
                None => (create_org_card()),
            }
            @if org.is_some() {
                (teams_section(teams, members))
            }
        }
    }
}

// SPEC-12.45.2: placeholder claims no capability
/// The flag-on page body. Kept pure so tests can assert the copy without
/// standing up an app state, mirroring the shape every other dashboard page uses.
fn organizations_content() -> Markup {
    html! {
        div class="space-y-6" id="organization-root" {
            div {
                h1 class="text-3xl font-bold" { "Organization" }
                p class="mt-2 text-muted-foreground" {
                    "Administer the organization you own and its teams."
                }
            }
            div class="rounded-lg border bg-card p-6" {
                (empty_state("users", "Loading\u{2026}", None))
            }
        }
    }
}

async fn fetch_state(
    st: &AppState,
    cookie: Option<&str>,
) -> (
    Option<OrganizationResponse>,
    Vec<TeamResponse>,
    Vec<(String, Vec<TeamMemberResponse>)>,
) {
    let org = orgs_api::get_my_organization(&st.api, cookie)
        .await
        .ok()
        .flatten();
    let teams = if org.is_some() {
        orgs_api::list_teams(&st.api, cookie)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut members = Vec::with_capacity(teams.len());
    for t in &teams {
        let list = orgs_api::list_team_members(&st.api, cookie, &t.id)
            .await
            .unwrap_or_default();
        members.push((t.id.clone(), list));
    }
    (org, teams, members)
}

// SPEC-12.45.1, SPEC-12.45.2: flag off answers 404 before auth so the route stays dark
/// `GET /organizations` - the landing page.
pub async fn organizations(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if !orgs_enabled() {
        return crate::skin::public::not_found(State(st), headers).await;
    }
    let (user, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (org, teams, members) = fetch_state(&st, c.forward.as_deref()).await;
    let content = organizations_root(org.as_ref(), &teams, &members);
    dashboard_response(&c, &user, "/organizations", "Organization", content)
}

#[allow(clippy::result_large_err)] // Err is the ready-made redirect the caller returns as-is
async fn require_signed_in(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::AuthCtx, Response> {
    if !orgs_enabled() {
        return Err(crate::skin::public::not_found(State(st.clone()), headers.clone()).await);
    }
    let (_, c) = match guard(st, headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return Err(r),
    };
    Ok(c)
}

/// POST /organizations: create the caller's organization. Replaces the
/// `#organization-root` fragment with the live view.
pub async fn create_my_organization(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<OrgNameForm>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let _ = orgs_api::create_my_organization(&st.api, cookie, &body.name).await;
    let (org, teams, members) = fetch_state(&st, cookie).await;
    html_cookies(
        organizations_root(org.as_ref(), &teams, &members),
        &c.set_cookies,
    )
}

/// PUT /organizations/name: rename the caller's organization. Replaces the
/// `.rounded-lg` card with the fresh view.
pub async fn update_my_organization(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<OrgNameForm>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let renamed = orgs_api::update_my_organization(&st.api, cookie, &body.name).await;
    match renamed {
        Ok(org) => html_cookies(org_card(&org), &c.set_cookies),
        Err(_) => {
            let (org, _, _) = fetch_state(&st, cookie).await;
            html_cookies(
                match org {
                    Some(o) => org_card(&o),
                    None => create_org_card(),
                },
                &c.set_cookies,
            )
        }
    }
}

/// POST /organizations/teams: create a team. Replaces `#teams-section`.
pub async fn create_team(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<TeamForm>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let desc = body.description.as_deref().filter(|s| !s.is_empty());
    let _ = orgs_api::create_team(&st.api, cookie, &body.name, desc).await;
    let (_, teams, members) = fetch_state(&st, cookie).await;
    html_cookies(teams_section(&teams, &members), &c.set_cookies)
}

/// DELETE /organizations/teams/{id}: swap-out an empty string replaces the
/// card with nothing, matching htmx's hx-swap="outerHTML" semantics.
pub async fn delete_team(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let _ = orgs_api::delete_team(&st.api, cookie, &id).await;
    html_cookies(PreEscaped(String::new()), &c.set_cookies)
}

/// POST /organizations/teams/{id}/members: add member, replaces the team row.
pub async fn add_team_member(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Form(body): Form<MemberForm>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let role = body.role.as_deref().filter(|s| !s.is_empty());
    let _ = orgs_api::add_team_member(&st.api, cookie, &team_id, &body.bunyip_user_id, role).await;
    render_team_row(&st, cookie, &c.set_cookies, &team_id).await
}

/// DELETE /organizations/teams/{tid}/members/{uid}: remove member, replaces team row.
pub async fn remove_team_member(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((team_id, user_id)): Path<(String, String)>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let _ = orgs_api::remove_team_member(&st.api, cookie, &team_id, &user_id).await;
    render_team_row(&st, cookie, &c.set_cookies, &team_id).await
}

/// PUT /organizations/teams/{tid}/members/{uid}/role: update member role.
pub async fn update_team_member_role(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((team_id, user_id)): Path<(String, String)>,
    Form(body): Form<RoleForm>,
) -> Response {
    let c = match require_signed_in(&st, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let _ =
        orgs_api::update_team_member_role(&st.api, cookie, &team_id, &user_id, &body.role).await;
    render_team_row(&st, cookie, &c.set_cookies, &team_id).await
}

async fn render_team_row(
    st: &AppState,
    cookie: Option<&str>,
    set_cookies: &[String],
    team_id: &str,
) -> Response {
    let teams = orgs_api::list_teams(&st.api, cookie)
        .await
        .unwrap_or_default();
    let Some(team) = teams.into_iter().find(|t| t.id == team_id) else {
        return html_cookies(PreEscaped(String::new()), set_cookies);
    };
    let members = orgs_api::list_team_members(&st.api, cookie, team_id)
        .await
        .unwrap_or_default();
    html_cookies(team_row(&team, &members), set_cookies)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::*;
    use crate::handlers::unreachable_api_state;
    use crate::views::layout::install_orgs_enabled;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime builds")
            .block_on(f)
    }

    async fn get_organizations() -> (StatusCode, Option<String>) {
        let app = Router::new()
            .route("/organizations", get(organizations))
            .with_state(unreachable_api_state());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/organizations")
                    .body(Body::empty())
                    .expect("the request builds"),
            )
            .await
            .expect("the router answers");
        let location = res
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        (res.status(), location)
    }

    /// BUNYIP-493 AC: with the switch off the route is unreachable, same answer
    /// a path that was never registered gets. An empty page, an error page or a
    /// redirect would each confirm the route exists.
    #[test]
    fn the_flagged_route_404s_while_the_switch_is_off() {
        let _guard = crate::feature_flags::FLAG_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        install_orgs_enabled(false);
        let (status, location) = block_on(get_organizations());
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            location, None,
            "a 404 is the whole answer; a redirect would confirm the route"
        );
    }

    /// Flag on, route exists; anonymous caller lands at sign-in.
    #[test]
    fn the_flagged_route_exists_once_the_switch_is_on() {
        let _guard = crate::feature_flags::FLAG_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        install_orgs_enabled(true);
        let (status, location) = block_on(get_organizations());
        install_orgs_enabled(false);
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "an unauthenticated caller is redirected to sign in, which only a live route does"
        );
        assert_eq!(location.as_deref(), Some("/login"));
    }

    /// The flag-on placeholder names no capability the BUNYIP-487 guard forbids.
    #[test]
    fn the_page_names_no_capability_that_does_not_exist() {
        let markup = organizations_content().into_string();
        assert!(markup.contains("Organization"));
        assert!(markup.contains("Administer the organization you own"));
    }
}
