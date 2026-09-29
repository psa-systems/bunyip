//! Admin panel: Feature Toggles (BUNYIP-840) and their review screen
//! (BUNYIP-843).
//!
//! One row per entry in bunyip-api's feature-toggle registry, each its own form
//! posting to `/admin/features`. Any admin sees the states; only the super admin
//! can flip one, which the API enforces again. A feature nobody has decided yet
//! is "New": the super admin works through those one card at a time on
//! `/admin/features/review`, a server-rendered stack that needs no JavaScript.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::{AdminFeatureToggle, AdminFeatureToggleList};
use crate::feature_flags;
use crate::handlers::{admin_guard, admin_response, admin_response_without_review_reminder};
use crate::util::{rel_time, urlenc};
use crate::views::layout::{admin_block, FEATURE_REVIEW_PATH};
use crate::views::ui::{badge, button_class, empty_state, error_box, icon, toggle_switch_field};
use crate::web::{redirect_cookies, AppState};

use super::refuse_non_super_admin;

/// Who changed the toggle and when, or that nobody has.
fn last_changed(t: &AdminFeatureToggle) -> Markup {
    html! {
        p class="text-xs text-muted-foreground" {
            @match (&t.updated_at, &t.updated_by_email) {
                (Some(at), Some(by)) => { "Last changed by " (by) " " (rel_time(at)) }
                (Some(at), None) => { "Last changed " (rel_time(at)) }
                _ => { "Never changed. Off by default." }
            }
        }
    }
}

fn feature_toggle_row(t: &AdminFeatureToggle, editable: bool) -> Markup {
    let id = format!("feature-{}", t.key);
    admin_block(
        &t.label,
        Some(&t.help),
        html! {
            div class="flex flex-wrap items-center justify-between gap-4" {
                @if editable {
                    form method="post" action="/admin/features" class="flex items-center gap-3" {
                        input type="hidden" name="key" value=(t.key);
                        @if !t.decided { (badge("default", "New")) }
                        (toggle_switch_field(&id, "enabled", t.enabled, &t.label))
                        label for=(id) class="text-sm font-medium" { "Enabled" }
                        button type="submit" class=(button_class("default", "sm", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                } @else {
                    div class="flex items-center gap-2" {
                        @if !t.decided { (badge("default", "New")) }
                        @if t.enabled { (badge("success", "On")) } @else { (badge("secondary", "Off")) }
                        span class="text-xs text-muted-foreground" { "Only the super admin can change this." }
                    }
                }
                (last_changed(t))
            }
        },
    )
}

pub(super) fn feature_toggles_content(
    list: &AdminFeatureToggleList,
    reachable: bool,
    editable: bool,
) -> Markup {
    let pending = list.toggles.iter().filter(|t| !t.decided).count();
    html! {
        div class="space-y-6" {
            div class="flex flex-wrap items-start justify-between gap-4" {
                div {
                    h1 class="text-3xl font-bold" { "Feature Toggles" }
                    p class="mt-2 text-muted-foreground" { "Switch a whole feature on or off for this deployment. Off means hidden: its pages return 404 and its links are not shown. A change is live everywhere within a minute, with no restart." }
                }
                @if reachable && editable && pending > 0 {
                    a href=(FEATURE_REVIEW_PATH) class=(button_class("default", "default", "")) { "Review new features (" (pending) ")" }
                }
            }
            @if !reachable {
                (error_box("Could not reach the API to load the feature toggles."))
            } @else if list.toggles.is_empty() {
                (empty_state("sliders-horizontal", "No feature toggles.", None))
            } @else {
                @for t in &list.toggles { (feature_toggle_row(t, editable)) }
            }
        }
    }
}

async fn load_toggles(st: &AppState, cookie: Option<&str>) -> Option<AdminFeatureToggleList> {
    match admin_api::feature_toggles(&st.api, cookie).await {
        Ok(list) => Some(list),
        Err(e) => {
            tracing::warn!(
                endpoint = "/v1/admin/feature-toggles",
                error = %e.message,
                code = %e.code,
                "feature toggles unavailable on the Feature Toggles pages"
            );
            None
        }
    }
}

pub async fn feature_toggles(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = load_toggles(&st, c.forward.as_deref()).await;
    let reachable = data.is_some();
    let list = data.unwrap_or_default();
    let content = feature_toggles_content(&list, reachable, user.is_super_admin);
    admin_response(&c, &user, "/admin/features", "Feature Toggles", content)
}

/// One row's submission. An unticked switch is absent from the body, which is
/// a real "off" because every row form renders the control.
#[derive(Deserialize)]
pub struct FeatureToggleForm {
    pub key: String,
    #[serde(default)]
    pub enabled: Option<String>,
}

pub async fn feature_toggle_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<FeatureToggleForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/features") {
        return refusal;
    }
    let target = match admin_api::set_feature_toggle(
        &st.api,
        c.forward.as_deref(),
        f.key.trim(),
        f.enabled.is_some(),
    )
    .await
    {
        Ok(()) => {
            // A first save is also a decision, so the reminder count moves now.
            feature_flags::refresh_now(&st.api).await;
            "/admin/features?toast_ok=Feature%20toggle%20saved".to_string()
        }
        Err(e) => format!("/admin/features?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

// ---- review screen (BUNYIP-843) ------------------------------------------

/// The keys set aside with "Decide later" on this visit, carried in `?skip=`.
/// Anything that is not a plausible key is dropped, so the value never reaches
/// markup or a URL unchecked.
pub(super) fn parse_skip(raw: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for key in raw.split(',').map(str::trim) {
        let plausible = !key.is_empty()
            && key.len() <= 64
            && key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if plausible && !keys.iter().any(|k| k == key) {
            keys.push(key.to_string());
        }
    }
    keys
}

/// The review URL carrying `skip`, or the bare path when nothing is skipped.
fn review_url(skip: &[String]) -> String {
    if skip.is_empty() {
        FEATURE_REVIEW_PATH.to_string()
    } else {
        format!("{FEATURE_REVIEW_PATH}?skip={}", urlenc(&skip.join(",")))
    }
}

/// A plain card for the terminal states of the review stack.
fn review_end_card(heading: &str, message: &str, actions: Markup) -> Markup {
    admin_block(
        heading,
        Some(message),
        html! { div class="flex flex-wrap items-center gap-3" { (actions) } },
    )
}

/// The top card: the first undecided feature not skipped on this visit.
fn review_card(
    t: &AdminFeatureToggle,
    environment: &str,
    skip: &[String],
    position: usize,
    total: usize,
) -> Markup {
    let mut later = skip.to_vec();
    later.push(t.key.clone());
    admin_block(
        &t.label,
        Some(&t.help),
        html! {
            div class="space-y-4" {
                div class="flex items-center justify-between gap-3" {
                    (badge("default", "New"))
                    span class="text-xs text-muted-foreground" { (position) " of " (total) }
                }
                @if !environment.is_empty() {
                    p class="text-sm" { "Applies to this environment: " span class="font-medium" { (environment) } }
                }
                form method="post" action=(FEATURE_REVIEW_PATH) class="flex flex-wrap items-center gap-3" {
                    input type="hidden" name="key" value=(t.key);
                    input type="hidden" name="skip" value=(skip.join(","));
                    (toggle_switch_field("review-enabled", "enabled", false, &t.label))
                    label for="review-enabled" class="text-sm font-medium" { "Enabled" }
                    button type="submit" class=(button_class("default", "sm", "")) { "Save and next" }
                    a href=(review_url(&later)) class=(button_class("ghost", "sm", "")) { "Decide later" }
                }
            }
        },
    )
}

/// The review screen body. `None` is an unreachable API; the three states of
/// the stack are a top card, "skipped for now" and "all caught up".
pub(super) fn feature_review_content(
    list: Option<&AdminFeatureToggleList>,
    skip: &[String],
) -> Markup {
    let back = html! {
        a href="/admin/features" class=(button_class("outline", "sm", "")) { "Back to Feature Toggles" }
    };
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Review New Features" }
                p class="mt-2 text-muted-foreground" { "Every new feature ships off. Decide whether this environment turns it on; the decision is recorded and applies to every user." }
            }
            @match list {
                None => (error_box("Could not reach the API to load the feature toggles.")),
                Some(list) => {
                    @let undecided: Vec<&AdminFeatureToggle> = list.toggles.iter().filter(|t| !t.decided).collect();
                    @let remaining: Vec<&AdminFeatureToggle> = undecided.iter().copied().filter(|t| !skip.contains(&t.key)).collect();
                    div class="relative mx-auto w-full max-w-xl pb-6" {
                        @if remaining.len() > 2 {
                            div aria-hidden="true" class="absolute inset-x-8 top-6 bottom-0 rounded-lg border bg-card/60 shadow-sm" {}
                        }
                        @if remaining.len() > 1 {
                            div aria-hidden="true" class="absolute inset-x-4 top-3 bottom-3 rounded-lg border bg-card/80 shadow-sm" {}
                        }
                        div class="relative" {
                            @if let Some(top) = remaining.first() {
                                (review_card(top, &list.environment, skip, undecided.len() - remaining.len() + 1, undecided.len()))
                            } @else if undecided.is_empty() {
                                (review_end_card("All caught up", "Every feature has a decision.", back))
                            } @else {
                                @let waiting = if undecided.len() == 1 {
                                    "One feature is still waiting for a decision.".to_string()
                                } else {
                                    format!("{} features are still waiting for a decision.", undecided.len())
                                };
                                (review_end_card(
                                    "Skipped for now",
                                    &waiting,
                                    html! {
                                        a href=(FEATURE_REVIEW_PATH) class=(button_class("default", "sm", "")) { "Start again" }
                                        (back)
                                    },
                                ))
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct FeatureReviewQuery {
    #[serde(default)]
    pub skip: String,
}

pub async fn feature_review(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FeatureReviewQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/features") {
        return refusal;
    }
    let list = load_toggles(&st, c.forward.as_deref()).await;
    let content = feature_review_content(list.as_ref(), &parse_skip(&q.skip));
    admin_response_without_review_reminder(
        &c,
        &user,
        "/admin/features",
        "Review New Features",
        content,
    )
}

/// One card's decision. An unticked switch is absent, which is a real "off".
#[derive(Deserialize)]
pub struct FeatureReviewForm {
    pub key: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub skip: String,
}

pub async fn feature_review_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<FeatureReviewForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/features") {
        return refusal;
    }
    let back = review_url(&parse_skip(&f.skip));
    let sep = if back.contains('?') { '&' } else { '?' };
    let target = match admin_api::set_feature_toggle(
        &st.api,
        c.forward.as_deref(),
        f.key.trim(),
        f.enabled.is_some(),
    )
    .await
    {
        Ok(()) => {
            // Drop the reminder in this process now rather than within a minute.
            feature_flags::refresh_now(&st.api).await;
            format!("{back}{sep}toast_ok=Decision%20saved")
        }
        Err(e) => format!("{back}{sep}toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::extract::Path;
    use axum::http::{header, Request, StatusCode};
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::handlers::test_state;

    fn toggle(key: &str, decided: bool) -> AdminFeatureToggle {
        serde_json::from_value(json!({
            "key": key, "label": format!("Label {key}"), "help": format!("Help {key}"),
            "enabled": false, "decided": decided
        }))
        .unwrap()
    }

    fn list(toggles: Vec<AdminFeatureToggle>) -> AdminFeatureToggleList {
        AdminFeatureToggleList {
            environment: "staging".into(),
            toggles,
        }
    }

    #[test]
    fn the_first_undecided_feature_is_the_top_card_unchecked() {
        let l = list(vec![
            toggle("decided_one", true),
            toggle("first_new", false),
            toggle("second_new", false),
            toggle("third_new", false),
        ]);
        let html = feature_review_content(Some(&l), &[]).into_string();
        assert!(html.contains("Label first_new") && !html.contains("Label second_new"));
        assert!(html.contains("1 of 3"), "{html}");
        assert!(html
            .contains(r#"Applies to this environment: <span class="font-medium">staging</span>"#));
        assert!(html.contains(">New<"));
        let input = html
            .split_once(r#"id="review-enabled""#)
            .expect("the toggle renders")
            .1
            .split_once('>')
            .unwrap()
            .0;
        assert!(!input.contains("checked"), "off by default: {input}");
        assert!(html.contains(r#"action="/admin/features/review""#));
        assert!(html.contains("Save and next"));
        assert!(html.contains(r#"href="/admin/features/review?skip=first_new""#));
        assert_eq!(
            html.matches(r#"aria-hidden="true" class="absolute"#)
                .count(),
            2,
            "two offset cards show that more remain"
        );
    }

    #[test]
    fn decide_later_moves_to_the_next_card_without_recording() {
        let l = list(vec![
            toggle("first_new", false),
            toggle("second_new", false),
        ]);
        let skip = parse_skip("first_new");
        let html = feature_review_content(Some(&l), &skip).into_string();
        assert!(html.contains("Label second_new") && !html.contains("Label first_new"));
        assert!(html.contains("2 of 2"));
        assert!(html.contains(r#"name="skip" value="first_new""#));
        assert!(html.contains("?skip=first_new%2Csecond_new"));

        let all_skipped = parse_skip("first_new,second_new");
        let html = feature_review_content(Some(&l), &all_skipped).into_string();
        assert!(html.contains("Skipped for now") && html.contains("2 features are still waiting"));
        assert!(!html.contains("Save and next"));
    }

    #[test]
    fn nothing_left_is_all_caught_up() {
        let l = list(vec![toggle("done", true)]);
        let html = feature_review_content(Some(&l), &[]).into_string();
        assert!(html.contains("All caught up"));
        assert!(html.contains(r#"href="/admin/features""#));
        let down = feature_review_content(None, &[]).into_string();
        assert!(down.contains("Could not reach the API to load the feature toggles."));
    }

    #[test]
    fn a_skip_list_keeps_only_plausible_keys() {
        assert_eq!(parse_skip(" a_b , a_b,,<x>,Upper,ok9 "), vec!["a_b", "ok9"]);
        assert!(parse_skip("").is_empty());
    }

    /// A stand-in for bunyip-api: `/v1/users/me` answers an admin whose
    /// super-admin flag is `super_admin`, and every toggle write is counted.
    async fn mock_api(super_admin: bool) -> (String, Arc<AtomicUsize>) {
        let writes = Arc::new(AtomicUsize::new(0));
        let me = move || async move {
            Json(json!({"data": {
                "id": "u1", "email": "admin@example.com", "role": "admin",
                "email_verified": true, "two_factor_enabled": true,
                "first_name": "Ada", "last_name": "Lovelace",
                "is_super_admin": super_admin
            }}))
        };
        async fn toggles() -> Json<Value> {
            Json(json!({"data": {"environment": "staging", "toggles": [
                {"key": "tenant_hostnames", "label": "Tenant Hostnames", "help": "h",
                 "enabled": false, "decided": false}
            ]}}))
        }
        let counter = Arc::clone(&writes);
        let write = move |Path(key): Path<String>| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(json!({"data": {"key": key, "enabled": true, "decided": true}}))
            }
        };
        let router = Router::new()
            .route("/v1/users/me", get(me))
            .route("/v1/admin/feature-toggles", get(toggles))
            .route("/v1/admin/feature-toggles/:key", put(write));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the mock API binds a port");
        let addr = listener.local_addr().expect("a local address");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("the mock API serves");
        });
        (format!("http://{addr}"), writes)
    }

    fn app(api_url: &str) -> Router {
        Router::new()
            .route(
                "/admin/features/review",
                get(feature_review).post(feature_review_save),
            )
            .with_state(test_state(api_url))
    }

    fn get_review() -> Request<Body> {
        Request::builder()
            .uri("/admin/features/review")
            .header(header::COOKIE, "session=abc")
            .body(Body::empty())
            .unwrap()
    }

    fn post_review() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/admin/features/review")
            .header(header::COOKIE, "session=abc")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("key=tenant_hostnames&enabled=true&skip="))
            .unwrap()
    }

    fn location(res: &Response) -> String {
        res.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// Negative case: a plain admin is sent back to Feature Toggles on both
    /// methods, and nothing reaches the API.
    #[tokio::test]
    async fn a_plain_admin_is_redirected_and_nothing_is_saved() {
        let (api, writes) = mock_api(false).await;
        let res = app(&api).oneshot(get_review()).await.unwrap();
        assert!(res.status().is_redirection());
        assert!(location(&res).starts_with("/admin/features?toast_err="));
        let res = app(&api).oneshot(post_review()).await.unwrap();
        assert!(res.status().is_redirection());
        assert!(location(&res).starts_with("/admin/features?toast_err="));
        assert_eq!(writes.load(Ordering::SeqCst), 0, "no write reached the API");
    }

    /// The super admin gets the card, and "Save and next" records the decision
    /// and returns to the stack.
    #[tokio::test]
    async fn the_super_admin_reviews_and_saves() {
        let (api, writes) = mock_api(true).await;
        let res = app(&api).oneshot(get_review()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        assert!(body.contains("Tenant Hostnames") && body.contains("1 of 1"));
        assert!(
            !body.contains("data-feature-review-pill"),
            "the review screen never carries its own reminder"
        );

        let res = app(&api).oneshot(post_review()).await.unwrap();
        assert!(res.status().is_redirection());
        assert!(location(&res).starts_with("/admin/features/review?toast_ok="));
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "the decision was recorded"
        );
    }
}
