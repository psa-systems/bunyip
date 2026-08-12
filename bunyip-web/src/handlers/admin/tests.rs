//! Admin panel unit tests.
//!
//! DEV-517 split `handlers/admin.rs` into one module per section. These markup
//! and request-body tests each reach across several of those sections, so they
//! stay together here rather than being torn apart. The glob imports below
//! re-expose the per-section items under a single name space, which is what the
//! `use super::...` lines inside each test module resolve against.

use serde_json::json;

use crate::api::types::*;
use crate::views::layout::{admin_block, admin_block_grid};

use super::application_groups::*;
use super::applications::*;
use super::auto_ban_settings::*;
use super::email_config::*;
use super::error_log::*;
use super::feedback::*;
use super::ip_bans::*;
use super::memberships::*;
use super::rate_limits::*;
use super::stripe::*;
use super::tier_settings::*;
use super::users::*;
use super::*;

#[cfg(test)]
mod request_body_tests {
    use super::*;

    fn blank_email_form() -> EmailSettingsForm {
        EmailSettingsForm {
            enabled: "false".into(),
            smtp_host: String::new(),
            smtp_port: String::new(),
            smtp_tls: "implicit".into(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_email: String::new(),
            from_name: String::new(),
            admin_notification_emails: String::new(),
        }
    }

    #[test]
    fn email_body_always_sends_enabled_and_omits_blanks() {
        let mut f = blank_email_form();
        f.enabled = "true".into();
        f.smtp_host = "  smtp.example.com  ".into();
        f.smtp_port = "587".into();
        f.smtp_tls = "starttls".into();
        let body = email_update_body(&f).expect("valid");
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["smtp_host"], json!("smtp.example.com")); // trimmed
        assert_eq!(body["smtp_port"], json!(587));
        assert_eq!(body["smtp_tls"], json!("starttls"));
        // Blank optional fields are omitted so the API keeps the existing value.
        assert!(body.get("smtp_username").is_none());
        assert!(body.get("smtp_password").is_none());
        assert!(body.get("from_email").is_none());
    }

    #[test]
    fn email_body_rejects_bad_port_and_email() {
        let mut f = blank_email_form();
        f.smtp_port = "70000".into();
        assert!(email_update_body(&f).is_err());

        let mut f = blank_email_form();
        f.from_email = "notanemail".into();
        assert!(email_update_body(&f).is_err());

        // enabled=false is still sent explicitly (the toggle works both ways).
        let body = email_update_body(&blank_email_form()).expect("valid");
        assert_eq!(body["enabled"], json!(false));
    }

    #[test]
    fn update_body_omits_empty_but_always_sends_forgejo_package() {
        // Empty optional inputs are dropped so the backend keeps the existing
        // column; forgejo_package is always present as the clear-to-NULL sentinel.
        let f = DistributionForm {
            artifact_source: "release".into(),
            forgejo_owner: "acme".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["artifact_source"], json!("release"));
        assert_eq!(body["forgejo_owner"], json!("acme"));
        assert_eq!(body["forgejo_package"], json!(""));
        assert!(body.get("forgejo_repo").is_none());
        assert!(body.get("oci_image_owner").is_none());
        // Unchecked checkbox (absent field) is sent as false, not omitted, so
        // the toggle works in both directions.
        assert_eq!(body["is_hosted"], json!(false));
    }

    #[test]
    fn update_body_sends_set_forgejo_package_and_trims() {
        let f = DistributionForm {
            artifact_source: "generic_package".into(),
            forgejo_package: "  mypkg  ".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["forgejo_package"], json!("mypkg"));
    }

    #[test]
    fn update_body_clears_package_on_release_even_if_prefilled() {
        // Switching a generic_package app to release must not re-send the stale
        // package, which would fail backend validation.
        let f = DistributionForm {
            artifact_source: "release".into(),
            forgejo_package: "leftover-pkg".into(),
            is_hosted: "true".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["forgejo_package"], json!(""));
        assert_eq!(body["is_hosted"], json!(true));
    }

    #[test]
    fn create_body_requires_identity_and_omits_empty_package() {
        // A new row has nothing to clear, so an empty forgejo_package is omitted
        // (an empty string would fail backend non-empty validation).
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            ..Default::default()
        };
        let body = create_app_body(&f).expect("create_app_body");
        assert_eq!(body["name"], json!("Mokosh"));
        assert_eq!(body["slug"], json!("mokosh"));
        assert_eq!(body["display_name"], json!("Mokosh"));
        assert_eq!(body["container_name"], json!("mokosh"));
        assert!(body.get("forgejo_package").is_none());
        assert!(body.get("forgejo_owner").is_none());
        // Unchecked "Hosted app" creates a catalog-only product (is_hosted=false)
        // instead of inheriting the DB default of true.
        assert_eq!(body["is_hosted"], json!(false));
    }

    #[test]
    fn create_body_sends_generic_package_and_hosted_flag() {
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            artifact_source: "generic_package".into(),
            forgejo_package: "mokosh-cli".into(),
            is_hosted: "true".into(),
            ..Default::default()
        };
        let body = create_app_body(&f).expect("create_app_body");
        assert_eq!(body["forgejo_package"], json!("mokosh-cli"));
        assert_eq!(body["is_hosted"], json!(true));
    }

    #[test]
    fn create_body_rejects_junk_slug_and_oversize_name() {
        // BUNYIP-112: junk slug and over-length name surface as inline edge
        // errors, not raw 500s on a DB cap or silent acceptance.
        let mut f = CreateAppForm {
            name: "Mokosh".into(),
            slug: " $$$ ".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            ..Default::default()
        };
        assert!(create_app_body(&f).is_err());
        f.slug = "mokosh".into();
        f.name = "a".repeat(300);
        assert!(create_app_body(&f).is_err());
    }

    #[test]
    fn update_body_sends_detail_fields_trimmed_and_omits_empty() {
        // The descriptive fields are now editable from the admin form; set ones
        // are sent (trimmed) and blank ones are omitted so the backend keeps the
        // existing column value.
        let f = DistributionForm {
            description: "  A great app  ".into(),
            icon_url: "https://example.com/icon.png".into(),
            release_notes_url: "  https://dev.a8n.run/psa-systems/mokosh-server/releases  ".into(),
            maintenance_message: "Back at 5pm".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["description"], json!("A great app"));
        assert_eq!(body["icon_url"], json!("https://example.com/icon.png"));
        // BUNYIP-343: the release-notes URL is editable and sent trimmed.
        assert_eq!(
            body["release_notes_url"],
            json!("https://dev.a8n.run/psa-systems/mokosh-server/releases")
        );
        assert_eq!(body["maintenance_message"], json!("Back at 5pm"));
        assert!(body.get("subdomain").is_none());
        assert!(body.get("version").is_none());
        assert!(body.get("source_code_url").is_none());
    }

    #[test]
    fn create_body_sends_detail_fields() {
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            description: "Identity platform".into(),
            version: "1.2.3".into(),
            source_code_url: "https://dev.a8n.run/psa-systems/mokosh".into(),
            ..Default::default()
        };
        let body = create_app_body(&f).expect("create_app_body");
        assert_eq!(body["description"], json!("Identity platform"));
        assert_eq!(body["version"], json!("1.2.3"));
        assert_eq!(
            body["source_code_url"],
            json!("https://dev.a8n.run/psa-systems/mokosh")
        );
        assert!(body.get("icon_url").is_none());
    }
}

#[cfg(test)]
mod error_log_tests {
    use super::log_row;
    use crate::api::types::AdminErrorLog;
    use std::collections::BTreeMap;

    fn entry() -> AdminErrorLog {
        let mut fields = BTreeMap::new();
        fields.insert("action".to_string(), "login".to_string());
        AdminErrorLog {
            timestamp: "2026-07-02T12:00:00Z".into(),
            level: "ERROR".into(),
            target: "bunyip_api::handlers".into(),
            message: "rate limit exceeded".into(),
            category: Some("rate_limit".into()),
            route: Some("/v1/auth/login".into()),
            client: Some("1.2.3.4".into()),
            fields,
        }
    }

    // BUNYIP-327 AC: an error event renders with its message, category and the
    // client it is attributable to, and is always tagged as an error.
    #[test]
    fn renders_message_category_client_and_fields() {
        let html = log_row(&entry()).into_string();
        assert!(html.contains("rate limit exceeded"), "message shown");
        assert!(html.contains("rate_limit"), "category shown");
        assert!(html.contains("1.2.3.4"), "client shown");
        assert!(html.contains("/v1/auth/login"), "route shown");
        assert!(html.contains("action=login"), "extra fields shown");
        assert!(html.contains("Error"), "tagged as an error");
    }
}

#[cfg(test)]
mod ip_ban_tests {
    use super::ip_ban_row;
    use crate::api::types::AdminIpBan;

    fn ban() -> AdminIpBan {
        AdminIpBan {
            ip: "203.0.113.7".into(),
            reason: "10 requests to suspicious paths in 60s".into(),
            strikes: 3,
            banned_at: "2026-07-03T11:00:00Z".into(),
            expires_at: "2026-07-03T12:00:00Z".into(),
        }
    }

    // BUNYIP-320 AC: a ban row shows the IP, reason and strike count, and
    // carries an Unban button that POSTs the IP to the lift endpoint.
    #[test]
    fn renders_ip_reason_strikes_and_unban_action() {
        let html = ip_ban_row(&ban()).into_string();
        assert!(html.contains("203.0.113.7"), "IP shown");
        assert!(
            html.contains("10 requests to suspicious paths in 60s"),
            "reason shown"
        );
        assert!(html.contains("3 strikes"), "strike count shown");
        assert!(html.contains("Unban"), "unban button present");
        assert!(
            html.contains(r#"action="/admin/ip-bans/unban""#),
            "unban form targets the lift endpoint"
        );
        assert!(
            html.contains(r#"name="ip" value="203.0.113.7""#),
            "ip carried in the form body"
        );
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::{fmt_retry_secs, rate_limit_row};
    use crate::api::types::AdminRateLimit;

    fn user_throttle() -> AdminRateLimit {
        AdminRateLimit {
            action: "login".into(),
            key: "user@example.com".into(),
            user_id: Some("11111111-1111-1111-1111-111111111111".into()),
            user_email: Some("user@example.com".into()),
            ip: None,
            count: 6,
            max_requests: 5,
            window_start: "2026-07-03T11:00:00Z".into(),
            retry_after: 125,
        }
    }

    fn ip_throttle() -> AdminRateLimit {
        AdminRateLimit {
            action: "registration".into(),
            key: "203.0.113.9".into(),
            user_id: None,
            user_email: None,
            ip: Some("203.0.113.9".into()),
            count: 3,
            max_requests: 3,
            window_start: "2026-07-03T11:00:00Z".into(),
            retry_after: 40,
        }
    }

    // BUNYIP-317 AC: a throttle row shows the subject, action, count/cap and a
    // Reset button that POSTs the (action, key) pair to the reset endpoint.
    #[test]
    fn renders_subject_action_countcap_and_reset_action() {
        let html = rate_limit_row(&user_throttle(), None).into_string();
        assert!(html.contains("user@example.com"), "subject email shown");
        assert!(html.contains("Login"), "action shown title-cased");
        assert!(html.contains("6/5"), "count vs cap shown");
        assert!(html.contains("retry in 2m 5s"), "retry-in shown");
        assert!(html.contains("Reset"), "reset button present");
        assert!(
            html.contains(r#"action="/admin/rate-limits/reset""#),
            "reset form targets the reset endpoint"
        );
        assert!(
            html.contains(r#"name="action" value="login""#),
            "action carried in the form body"
        );
        assert!(
            html.contains(r#"name="key" value="user@example.com""#),
            "key carried in the form body"
        );
        // No return context on the standalone list.
        assert!(
            !html.contains(r#"name="return_user""#),
            "list rows carry no return-user field"
        );
    }

    // On the user-detail page the row carries the return-user id so the reset
    // redirects back to that page.
    #[test]
    fn user_detail_row_carries_return_user() {
        let html = rate_limit_row(
            &user_throttle(),
            Some("11111111-1111-1111-1111-111111111111"),
        )
        .into_string();
        assert!(
            html.contains(r#"name="return_user" value="11111111-1111-1111-1111-111111111111""#),
            "return-user id carried so the reset redirects back to the user page"
        );
    }

    // An IP-keyed throttle exposes the IP as the subject and never a user.
    #[test]
    fn ip_keyed_row_shows_ip_subject() {
        let html = rate_limit_row(&ip_throttle(), None).into_string();
        assert!(html.contains("203.0.113.9"), "ip subject shown");
        assert!(html.contains("Registration"), "action shown title-cased");
        assert!(
            html.contains(r#"name="key" value="203.0.113.9""#),
            "ip key carried in the form body"
        );
    }

    #[test]
    fn retry_secs_formats_compactly() {
        assert_eq!(fmt_retry_secs(0), "any moment");
        assert_eq!(fmt_retry_secs(45), "45s");
        assert_eq!(fmt_retry_secs(60), "1m");
        assert_eq!(fmt_retry_secs(125), "2m 5s");
    }

    // -- BUNYIP-405: admin users list row --------------------------------------

    const ROW_UID: &str = "11111111-1111-1111-1111-111111111111";

    fn admin_user(email: &str, verified: bool, admin: bool) -> crate::api::types::AdminUser {
        serde_json::from_value(serde_json::json!({
            "id": ROW_UID,
            "email": email,
            "role": if admin { "admin" } else { "subscriber" },
            "email_verified": verified,
            "two_factor_enabled": false,
            "membership_status": "none",
            "membership_tier": "standard",
            "lifetime_member": false,
            "created_at": "2026-01-01T00:00:00Z",
            "last_login_at": null,
            "grace_period_end": null,
        }))
        .expect("valid admin user json")
    }

    /// A suspended `AdminUser` (soft-deleted) built off the standard fixture.
    fn suspended_admin_user(email: &str) -> crate::api::types::AdminUser {
        let mut u = admin_user(email, true, false);
        u.suspended = true;
        u
    }

    #[test]
    fn active_user_row_links_to_detail_with_no_inline_actions() {
        let html = super::user_grid_row(&admin_user("ada@example.com", true, false)).into_string();
        // The whole row is a link into the per-user detail view.
        assert!(
            html.contains(&format!(r#"href="/admin/users/{ROW_UID}""#)),
            "active row links to the detail view"
        );
        assert!(html.contains("Verified"), "verified indicator shown");
        // Every management action lives on the detail view (BUNYIP-405): the list
        // row carries none of them, and no forms at all.
        for action in [
            "/role",
            "/reset-password",
            "/suspend",
            "/delete",
            "/lifetime",
            "/entitlements",
        ] {
            assert!(
                !html.contains(action),
                "active list row must not carry the {action} action"
            );
        }
        assert!(!html.contains("<form"), "active list row carries no forms");
    }

    #[test]
    fn unverified_user_row_shows_unverified_status() {
        let html = super::user_grid_row(&admin_user("new@example.com", false, false)).into_string();
        assert!(html.contains("Unverified"), "unverified status shown");
        assert!(!html.contains(">Verified<"));
    }

    #[test]
    fn suspended_user_row_keeps_reactivate_and_is_not_a_link() {
        let html = super::user_grid_row(&suspended_admin_user("gone@example.com")).into_string();
        assert!(
            html.contains(&format!(r#"action="/admin/users/{ROW_UID}/reactivate""#)),
            "suspended row keeps the inline Reactivate action"
        );
        assert!(html.contains("Suspended"), "suspended badge shown");
        // The detail view 404s for a soft-deleted user, so the suspended row is
        // intentionally not a link into it.
        assert!(
            !html.contains(&format!(r#"href="/admin/users/{ROW_UID}""#)),
            "suspended row is not a detail link"
        );
    }

    // -- BUNYIP-410: users + memberships consolidation --------------------------

    #[test]
    fn user_row_shows_membership_tier() {
        // The row carries the membership tier badge (the builder seeds "standard")
        // alongside the verification indicator.
        let html = super::user_grid_row(&admin_user("ada@example.com", true, false)).into_string();
        assert!(html.contains("Standard"), "tier badge shown on the row");
        assert!(html.contains("Verified"));
    }

    fn q(status: &str, tier: &str, verified: &str, search: &str) -> super::UsersQ {
        super::UsersQ::from_query(super::UserQuery {
            page: None,
            search: (!search.is_empty()).then(|| search.to_string()),
            status: (!status.is_empty()).then(|| status.to_string()),
            tier: (!tier.is_empty()).then(|| tier.to_string()),
            verified: (!verified.is_empty()).then(|| verified.to_string()),
            sort: None,
            dir: None,
            page_size: None,
        })
    }

    #[test]
    fn usersq_href_emits_only_nondefault_params() {
        // A clean, default state is a clean URL.
        assert_eq!(q("", "", "", "").href(), "/admin/users");
        // Filters appear; the default `active` status does not.
        let href = q("all", "lifetime", "verified", "ada").href();
        assert!(href.contains("status=all"));
        assert!(href.contains("tier=lifetime"));
        assert!(href.contains("verified=verified"));
        assert!(href.contains("search=ada"));
        // Default status is omitted.
        assert!(!q("active", "", "", "").href().contains("status="));
    }

    #[test]
    fn usersq_sort_toggles_then_switches_columns() {
        let base = q("", "", "", "");
        // First click on a column sorts ascending.
        let asc = base.with_sort("email");
        assert_eq!((asc.sort.as_str(), asc.dir.as_str()), ("email", "asc"));
        // Clicking the same column again flips to descending.
        let desc = asc.with_sort("email");
        assert_eq!(desc.dir, "desc");
        // Clicking a different column restarts ascending.
        let other = desc.with_sort("joined");
        assert_eq!((other.sort.as_str(), other.dir.as_str()), ("joined", "asc"));
    }

    #[test]
    fn usersq_is_filtered_only_when_narrowed() {
        assert!(!q("active", "", "", "").is_filtered(), "plain active view");
        assert!(q("all", "", "", "").is_filtered(), "non-default status");
        assert!(q("active", "lifetime", "", "").is_filtered(), "tier filter");
        assert!(
            q("active", "", "verified", "").is_filtered(),
            "verified filter"
        );
        assert!(q("active", "", "", "ada").is_filtered(), "search");
    }

    #[test]
    fn usersq_filter_change_resets_page() {
        let mut on_page_3 = q("", "", "", "");
        on_page_3.page = 3;
        assert_eq!(on_page_3.with_tier("lifetime").page, 1);
        assert_eq!(on_page_3.with_status("all").page, 1);
        assert_eq!(on_page_3.with_search("x").page, 1);
        // Paging itself does not reset the page.
        assert_eq!(on_page_3.with_page(4).page, 4);
    }

    #[test]
    fn users_panel_shows_count_filter_bar_and_sortable_headers() {
        let panel =
            super::users_panel(&q("active", "lifetime", "", ""), None, Some(13)).into_string();
        // Panel is the htmx swap target.
        assert!(panel.contains(r#"id="users-panel""#));
        // Segmented control + sortable headers present.
        assert!(panel.contains(r#"role="radiogroup""#));
        assert!(panel.contains("data-sort-header"));
        // An active tier filter renders a removable chip + Clear all.
        assert!(panel.contains("Tier: Lifetime"));
        assert!(panel.contains("Clear all"));
    }

    #[test]
    fn verified_filter_parses_tri_state() {
        assert_eq!(super::parse_verified_filter("verified"), Some(true));
        assert_eq!(super::parse_verified_filter("unverified"), Some(false));
        // Blank / absent / junk = no filter (both verified and unverified).
        assert_eq!(super::parse_verified_filter(""), None);
        assert_eq!(super::parse_verified_filter("anything"), None);
    }

    #[test]
    fn tier_label_maps_every_tier() {
        use crate::api::types::MembershipTier::*;
        assert_eq!(super::tier_label(&Lifetime), "Lifetime");
        assert_eq!(super::tier_label(&Free), "Free");
        assert_eq!(super::tier_label(&EarlyAdopter), "Early Adopter");
        assert_eq!(super::tier_label(&Standard), "Standard");
    }

    #[tokio::test]
    async fn memberships_redirects_to_filtered_users() {
        use axum::extract::Query;
        use axum::http::header::LOCATION;

        let loc = |resp: axum::response::Response| {
            assert!(resp.status().is_redirection(), "must be a redirect");
            resp.headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };

        // No tier -> the plain users list.
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: None,
        }))
        .await;
        assert_eq!(loc(r), "/admin/users");

        // A known tier is preserved as the users-list filter.
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: Some("lifetime".into()),
        }))
        .await;
        assert_eq!(loc(r), "/admin/users?tier=lifetime");

        // A junk tier falls back to the unfiltered list (matches the old page).
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: Some("not-a-tier".into()),
        }))
        .await;
        assert_eq!(loc(r), "/admin/users");
    }

    // -- BUNYIP-422: feedback list row + detail actions ------------------------

    const FB_ID: &str = "22222222-2222-2222-2222-222222222222";

    fn feedback_summary(status: &str) -> crate::api::types::AdminFeedbackSummary {
        serde_json::from_value(serde_json::json!({
            "id": FB_ID,
            "name": "Ada Lovelace",
            "email_masked": "a***@example.com",
            "subject": "A bug report",
            "message_excerpt": "Something went wrong when I clicked save.",
            "status": status,
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .expect("feedback summary fixture")
    }

    #[test]
    fn feedback_row_links_to_detail_with_no_inline_actions() {
        let html =
            super::feedback_row(&feedback_summary("new"), super::FeedbackTab::Active).into_string();
        // The whole row is a link into the detail view, carrying the tab slug.
        assert!(
            html.contains(&format!(r#"href="/admin/feedback/{FB_ID}?from=active""#)),
            "row links to the detail view with the tab slug"
        );
        // Status chip is shown; the summary content is present.
        assert!(html.contains("New"), "status chip rendered");
        assert!(html.contains("A bug report"), "subject shown");
        // Every triage action lives on the detail view now: the list row
        // carries no forms and none of the action endpoints.
        assert!(!html.contains("<form"), "list row carries no forms");
        for action in [
            "/status",
            "/mark-spam",
            "/unmark-spam",
            "/archive",
            "/delete",
        ] {
            assert!(
                !html.contains(action),
                "list row must not carry the {action} action"
            );
        }
    }

    #[test]
    fn feedback_row_carries_originating_tab_slug() {
        let html =
            super::feedback_row(&feedback_summary("new"), super::FeedbackTab::Spam).into_string();
        assert!(
            html.contains(&format!(r#"href="/admin/feedback/{FB_ID}?from=spam""#)),
            "row from the Spam tab links back with ?from=spam"
        );
    }

    #[test]
    fn feedback_detail_actions_are_tab_aware() {
        use crate::api::types::FeedbackStatus;
        // Active: review + close + archive + spam + delete, all redirecting home.
        let active =
            super::feedback_detail_actions(FB_ID, &FeedbackStatus::New, super::FeedbackTab::Active)
                .into_string();
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/status""#)));
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/mark-spam""#)));
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/delete""#)));
        assert!(active.contains("Close"));
        assert!(active.contains(r#"name="from" value="active""#));

        // A reviewed item offers Un-review rather than Reviewed.
        let reviewed = super::feedback_detail_actions(
            FB_ID,
            &FeedbackStatus::Reviewed,
            super::FeedbackTab::Active,
        )
        .into_string();
        assert!(reviewed.contains("Un-review"));

        // Spam tab: Not spam + archive + delete, redirecting back to Spam.
        let spam =
            super::feedback_detail_actions(FB_ID, &FeedbackStatus::New, super::FeedbackTab::Spam)
                .into_string();
        assert!(spam.contains("Not spam"));
        assert!(spam.contains(&format!(r#"action="/admin/feedback/{FB_ID}/unmark-spam""#)));
        assert!(spam.contains(r#"name="from" value="spam""#));
        assert!(!spam.contains("Close"), "spam tab has no Close action");

        // Closed tab: Re-open, redirecting back to Closed.
        let closed = super::feedback_detail_actions(
            FB_ID,
            &FeedbackStatus::Closed,
            super::FeedbackTab::Closed,
        )
        .into_string();
        assert!(closed.contains("Re-open"));
        assert!(closed.contains(r#"name="from" value="closed""#));
    }

    #[test]
    fn feedback_tab_from_query_round_trips() {
        for (slug, tab) in [
            ("active", super::FeedbackTab::Active),
            ("closed", super::FeedbackTab::Closed),
            ("spam", super::FeedbackTab::Spam),
            ("archive", super::FeedbackTab::Archive),
        ] {
            assert_eq!(super::FeedbackTab::from_query(Some(slug)), tab);
            assert_eq!(tab.query_slug(), slug);
        }
        // Absent / unknown falls back to Active.
        assert_eq!(
            super::FeedbackTab::from_query(None),
            super::FeedbackTab::Active
        );
        assert_eq!(
            super::FeedbackTab::from_query(Some("junk")),
            super::FeedbackTab::Active
        );
    }
}

#[cfg(test)]
mod two_column_layout_tests {
    // BUNYIP-415: the SSR analog of a wide/narrow visual-regression check is to
    // assert the responsive two-column grid class (two columns at `lg`, one
    // below) is present and that no fields were dropped when regrouping into
    // blocks. The list-screen conversions (rate limits, IP bans, entitlements)
    // reuse the same `lg:grid-cols-2` wrapper and are verified via screenshots.
    use super::*;

    #[test]
    fn admin_block_grid_is_responsive_two_column() {
        let grid = admin_block_grid(vec![
            admin_block("Alpha", None, maud::html! { "a" }),
            admin_block("Beta", Some("sub"), maud::html! { "b" }),
        ])
        .into_string();
        assert!(grid.contains("grid"));
        assert!(
            grid.contains("lg:grid-cols-2"),
            "two columns at lg, one below"
        );
        assert!(
            grid.contains(">Alpha<") && grid.contains(">Beta<"),
            "both block titles present"
        );
        assert!(grid.contains("sub"), "subtitle rendered when provided");
    }

    fn email_cfg() -> crate::api::types::EmailConfigResponse {
        serde_json::from_value(json!({
            "enabled": true, "smtp_host": "smtp.example.com", "smtp_port": 587,
            "smtp_tls": "starttls", "smtp_username": "u", "has_smtp_password": true,
            "from_email": "no-reply@example.com",
            "from_name": "Bunyip", "admin_notification_emails": ["ops@example.com"],
            "source": "environment"
        }))
        .unwrap()
    }

    #[test]
    fn smtp_password_field_is_a_fixed_mask_never_the_secret() {
        // BUNYIP-432: the field is write-only. When a password is set the
        // placeholder is a fixed-length mask (no last-4, no length hint); the
        // real value is not in the type or the markup at all.
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains(r#"placeholder="••••••••""#),
            "a fixed-length mask is shown when a password is set: {html}"
        );
        assert!(
            !html.contains("****") && !html.contains("(unchanged)"),
            "no masked/last-4 or old placeholder leaks into the page"
        );
        // The empty-password variant shows a distinct, non-secret placeholder.
        let mut none = email_cfg();
        none.has_smtp_password = false;
        let html_none = email_settings_content(Some(&none)).into_string();
        assert!(html_none.contains(r#"placeholder="Not set""#));
    }

    #[test]
    fn email_screen_uses_two_column_blocks() {
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains("lg:grid-cols-2"),
            "email settings render as a responsive two-column grid"
        );
        assert!(html.contains("SMTP Connection") && html.contains("Notifications"));
        for f in [
            "smtp_host",
            "smtp_port",
            "from_email",
            "admin_notification_emails",
        ] {
            assert!(html.contains(f), "field {f} preserved after regrouping");
        }
    }

    /// BUNYIP-433: the email page carries a Test connection control that POSTs to
    /// its own endpoint (a separate form from Save, so it tests saved settings).
    #[test]
    fn email_screen_has_test_connection_button() {
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains(r#"action="/admin/email/test""#),
            "Test connection posts to /admin/email/test"
        );
        assert!(html.contains("Test connection"), "button label present");
        // Distinct from the Save form so it submits no unsaved fields.
        assert!(
            html.matches("<form").count() >= 2,
            "test control is its own form, separate from Save"
        );
    }

    /// BUNYIP-508: a second, separate form sends a real message to the admin's
    /// own address, immediately below Test connection.
    #[test]
    fn email_screen_has_test_email_button() {
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains(r#"action="/admin/email/test-send""#),
            "Test email posts to /admin/email/test-send"
        );
        assert!(html.contains("Test email"), "button label present");
        assert!(
            html.contains("Sends a real test message to your own address"),
            "helper copy names what actually happens"
        );
        // Below Test connection, and its own form so it submits no fields.
        let probe = html
            .find(r#"action="/admin/email/test""#)
            .expect("probe form");
        let send = html
            .find(r#"action="/admin/email/test-send""#)
            .expect("send form");
        assert!(probe < send, "Test email sits below Test connection");
        assert!(
            html.matches("<form").count() >= 3,
            "send control is its own form"
        );
    }

    /// BUNYIP-508: a failed send arrives as a 200 with `ok: false`; the page
    /// must show the relay's reason in a red banner, never a green one. A 429
    /// arrives as an `Err` and renders through `ApiError::user_message`.
    #[test]
    fn test_email_failure_renders_the_error_banner() {
        let failed = crate::api::types::TestEmailResult {
            ok: false,
            message: "Email send error: 550 relay denied".into(),
        };
        let html = test_send_banner(Ok(failed)).into_string();
        assert!(
            html.contains("550 relay denied"),
            "the relay's reason reaches the page: {html}"
        );
        assert!(
            html.contains("destructive"),
            "rendered as an error banner: {html}"
        );

        let sent = crate::api::types::TestEmailResult {
            ok: true,
            message: "Test message sent to your address. Check your inbox.".into(),
        };
        let ok_html = test_send_banner(Ok(sent)).into_string();
        assert!(
            !ok_html.contains("destructive"),
            "a completed send renders the success banner: {ok_html}"
        );

        let throttled = crate::api::ApiError {
            status: 429,
            code: "RATE_LIMITED".into(),
            message: String::new(),
            retry_after: Some(120),
            request_id: None,
        };
        let throttled_html = test_send_banner(Err(throttled)).into_string();
        assert!(
            throttled_html.contains("Too many attempts") && throttled_html.contains("destructive"),
            "a throttled click is surfaced, not swallowed: {throttled_html}"
        );
    }

    fn auto_ban_cfg() -> crate::api::types::AutoBanConfigResponse {
        serde_json::from_value(json!({
            "enabled": true, "threshold": 10, "window_secs": 60,
            "ban_duration_secs": 3600, "source": "database"
        }))
        .unwrap()
    }

    #[test]
    fn auto_ban_screen_uses_two_column_blocks() {
        let cfg = auto_ban_cfg();
        let vals = AutoBanFormValues::from_config(&cfg);
        let html = auto_ban_settings_content(Some(&cfg), &vals, None).into_string();
        assert!(html.contains("lg:grid-cols-2"));
        assert!(html.contains("Detection") && html.contains("Enforcement"));
        for f in ["threshold", "window_secs", "ban_duration_secs"] {
            assert!(html.contains(f), "field {f} preserved after regrouping");
        }
    }

    fn tier_cfg() -> crate::api::types::TierConfigResponse {
        serde_json::from_value(json!({
            "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
            "standard_trial_days": 30, "free_price_id": null, "early_adopter_price_id": null,
            "standard_price_id": null, "source": "database",
            "lifetime_slots_used": 2, "early_adopter_slots_used": 1
        }))
        .unwrap()
    }

    fn tier_vals() -> TierFormValues {
        TierFormValues {
            lifetime_slots: "5".into(),
            early_adopter_slots: "5".into(),
            early_adopter_trial_days: "90".into(),
            standard_trial_days: "30".into(),
            free_price_id: String::new(),
            early_adopter_price_id: String::new(),
            standard_price_id: String::new(),
            lifetime_product_id: String::new(),
            early_adopter_product_id: String::new(),
            standard_product_id: String::new(),
        }
    }

    /// BUNYIP-524: a web-side tier config with the publish switch set to
    /// `pricing_enabled`, for the Stripe catalog-mapping tests.
    fn tier_cfg_pricing(pricing_enabled: bool) -> crate::api::types::TierConfigResponse {
        serde_json::from_value(json!({
            "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
            "standard_trial_days": 30, "source": "database",
            "lifetime_slots_used": 0, "early_adopter_slots_used": 0,
            "pricing_enabled": pricing_enabled
        }))
        .unwrap()
    }

    #[test]
    fn tier_settings_shows_slots_and_no_stripe_catalog() {
        // BUNYIP-417: the Stripe catalog mapping moved to the Stripe page, so
        // the Pricing tiers page keeps only slots + trial days and carries none of the
        // price/product-ID fields.
        let vals = tier_vals();
        let html = tier_settings_content(Some(&tier_cfg()), &vals, None).into_string();
        // BUNYIP-487: the page is labelled "Pricing tiers"; the route is
        // unchanged.
        assert!(html.contains("Pricing tiers"), "renamed heading");
        assert!(!html.contains("Tier Settings"), "old heading is gone");
        // BUNYIP-524: the publish switch moved to the Stripe catalog mapping, so
        // it is no longer on this page.
        assert!(
            !html.contains(r#"name="pricing_enabled""#),
            "Enable Pricing checkbox moved to the Stripe page"
        );
        assert!(
            html.contains(r#"action="/admin/tier-settings""#),
            "route unchanged so admin bookmarks keep working"
        );
        for f in [
            "lifetime_slots",
            "early_adopter_slots",
            "standard_trial_days",
        ] {
            assert!(html.contains(f), "slots/trials field {f} present");
        }
        assert!(
            !html.contains("Stripe catalog"),
            "catalog blocks moved to the Stripe page"
        );
        for f in [
            "free_price_id",
            "standard_product_id",
            "early_adopter_price_id",
        ] {
            assert!(
                !html.contains(f),
                "catalog field {f} no longer on the Pricing tiers page"
            );
        }
        // It links to where the mapping now lives.
        assert!(html.contains(r#"href="/admin/stripe""#));
    }

    #[test]
    fn catalog_publish_switch_reflects_the_saved_state() {
        // BUNYIP-524: the publish switch lives in the Stripe catalog mapping and
        // its `checked` attribute is driven by the saved `pricing_enabled`, so
        // it survives save + reload.
        let on =
            super::stripe_catalog_section(Ok(&tier_cfg_pricing(true)), None, Err("unavailable"))
                .into_string();
        let off =
            super::stripe_catalog_section(Ok(&tier_cfg_pricing(false)), None, Err("unavailable"))
                .into_string();
        assert!(
            on.contains(r#"name="pricing_enabled""#),
            "publish switch present in the catalog mapping"
        );
        assert!(on.contains("checked"), "checked when the switch is on");
        assert!(!off.contains("checked"), "unchecked when the switch is off");
    }

    // BUNYIP-515 / BUNYIP-524: the catalog mapping says what /pricing is serving
    // and, when it is serving nothing, which check failed. Several causes used to
    // render as one silent 404. The switch and this status now sit together.

    fn pricing_status(v: serde_json::Value) -> crate::api::types::PricingStatus {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn catalog_names_the_published_tiers() {
        let status = pricing_status(json!({
            "published": true,
            "tiers": [
                { "tier": "lifetime", "amount": 0, "currency": "usd", "interval": "month", "trial_days": 0 },
                { "tier": "standard", "amount": 300, "currency": "usd", "interval": "month", "trial_days": 30 },
            ],
            "reasons": [],
        }));
        let html = super::stripe_catalog_section(Ok(&tier_cfg_pricing(true)), None, Ok(&status))
            .into_string();
        assert!(html.contains("/pricing is live and advertising: Lifetime, Standard."));
    }

    #[test]
    fn catalog_lists_every_reason_it_is_unpublished() {
        let status = pricing_status(json!({
            "published": false,
            "tiers": [],
            "reasons": [
                { "code": "price_unresolved", "tier": "standard", "price_id": "price_1U33Rl",
                  "message": "Standard: price_1U33Rl is not visible under app tag `bunyip`. Check the id, or set that product's app_tag metadata in Stripe." },
                { "code": "price_unresolved", "tier": "early_adopter", "price_id": "price_old",
                  "message": "Early Adopter: price_old is archived in Stripe. Map an active price." },
            ],
        }));
        let html = super::stripe_catalog_section(Ok(&tier_cfg_pricing(false)), None, Ok(&status))
            .into_string();
        assert!(
            html.contains("app tag `bunyip`"),
            "the app-tag cause is named verbatim, tag included"
        );
        assert!(
            html.contains("price_old is archived in Stripe"),
            "each reason gets its own line, not a collapsed summary"
        );
        assert!(
            !html.contains("/pricing is live"),
            "nothing published means no success box"
        );
    }

    #[test]
    fn catalog_says_when_pricing_status_is_unreadable() {
        // The switch's whole point is publishing /pricing, so "no answer" must
        // not render as "nothing to report".
        let html = super::stripe_catalog_section(
            Ok(&tier_cfg_pricing(false)),
            None,
            Err("Could not reach the server."),
        )
        .into_string();
        assert!(html.contains("Could not load the pricing status"));
        assert!(
            html.contains("Could not reach the server."),
            "the underlying cause rides along"
        );
    }

    // BUNYIP-435: the remaining single-narrow-column settings screens adopt the
    // same block-grid layout. Assert the responsive grid, the block titles, that
    // every field survives the regroup, and that the old `max-w-md` cap is gone.

    #[test]
    fn application_form_uses_two_column_blocks() {
        let details = DetailsView {
            description: "d",
            icon_url: "i",
            subdomain: "s",
            version: "v",
            source_code_url: "src",
            release_notes_url: "notes",
            maintenance_message: "m",
        };
        let dist = DistView {
            artifact_source: "release",
            forgejo_owner: "o",
            forgejo_repo: "r",
            forgejo_package: "p",
            pinned_release_tag: "t",
            oci_image_owner: "oo",
            oci_image_name: "on",
            pinned_image_tag: "it",
        };

        // Edit page: no Identity block, Details | Distribution side by side.
        let edit = application_form(
            "/admin/applications/x/distribution",
            "Edit x",
            "blurb",
            None,
            true,
            &details,
            &dist,
            None,
            None,
        )
        .into_string();
        assert!(
            edit.contains("lg:grid-cols-2"),
            "application form renders a responsive two-column grid"
        );
        assert!(
            !edit.contains("max-w-md"),
            "the fixed narrow-column cap is removed so the form fills the width"
        );
        assert!(edit.contains(">Details<") && edit.contains(">Distribution<"));
        assert!(
            !edit.contains(">Identity<"),
            "no Identity block when editing"
        );
        // BUNYIP-460: the primary action is a bordered full-width footer and is
        // relabelled so it is unmistakably the Details + Distribution Save (not
        // the Group card's "Save group").
        assert!(
            edit.contains("border-t pt-6") && edit.contains("Save application"),
            "form actions render as a bordered footer with a scoped Save label"
        );
        // BUNYIP-460: Binary / Container are muted, nested subheads (not loud
        // section titles competing with the "Distribution" card title).
        assert!(
            edit.contains("Binary (Forgejo)") && edit.contains("Container (OCI)"),
            "distribution subsections are still present"
        );
        assert!(
            !edit.contains(r#"class="text-lg font-semibold pt-2""#),
            "the old loud subsection heading style is gone"
        );
        for f in [
            "description",
            "icon_url",
            "artifact_source",
            "oci_image_owner",
            "is_hosted",
        ] {
            assert!(edit.contains(f), "field {f} preserved");
        }

        // Create page: Identity fields lead as their own block.
        let identity = IdentityView {
            name: "n",
            slug: "sl",
            display_name: "dn",
            container_name: "cn",
        };
        let create = application_form(
            "/admin/applications",
            "New",
            "blurb",
            Some(&identity),
            false,
            &details,
            &dist,
            None,
            None,
        )
        .into_string();
        assert!(create.contains(">Identity<"), "Identity block on create");
        for f in ["name=\"name\"", "name=\"slug\"", "name=\"container_name\""] {
            assert!(create.contains(f), "identity field {f} preserved");
        }
    }

    // BUNYIP-473: the application list row uses one drag handle for reordering,
    // not the old stacked up/down chevrons (which swapped equal sort_orders and
    // did nothing). Assert the drag-and-drop markup is present and the old
    // swap-order control is gone, while the row's other controls survive.
    #[test]
    fn application_row_uses_drag_handle_not_chevrons() {
        let app: AdminApplication = serde_json::from_value(json!({
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "backup",
            "slug": "backup",
            "display_name": "Backup",
            "description": null,
            "icon_url": null,
            "is_active": true,
            "maintenance_mode": false,
            "maintenance_message": null,
            "subdomain": null,
            "container_name": "backup",
            "version": null,
            "source_code_url": null,
            "sort_order": 1,
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .expect("AdminApplication");

        let html = app_admin_row(&app).into_string();
        // One clear drag affordance.
        assert!(html.contains("data-reorder-item"), "row is a reorder item");
        assert!(
            html.contains("data-reorder-handle"),
            "row has a drag handle"
        );
        assert!(html.contains(r#"draggable="true""#), "row is draggable");
        assert!(html.contains(r#"data-app-id="11111111-1111-1111-1111-111111111111""#));
        assert!(
            html.contains("cursor-grab"),
            "grab-cursor affordance present"
        );
        // The broken control is gone.
        assert!(
            !html.contains("swap-order"),
            "the old swap-order form is removed"
        );
        assert!(
            !html.contains("Move up") && !html.contains("Move down"),
            "no stacked up/down chevron buttons"
        );
        // The row's other controls are untouched.
        assert!(html.contains("Toggle active"), "active toggle preserved");
        assert!(html.contains(">Edit<"), "edit link preserved");
    }

    #[test]
    fn group_form_uses_two_column_blocks() {
        let g = crate::api::types::ApplicationGroup {
            id: "g1".into(),
            name: "core".into(),
            slug: "core".into(),
            display_name: "Core".into(),
            description: Some("desc".into()),
            icon_url: Some("icon".into()),
            sort_order: 3,
        };
        let html = group_form("/admin/application-groups/g1", "Edit", Some(&g), None).into_string();
        assert!(
            html.contains("lg:grid-cols-2"),
            "group form renders a responsive two-column grid"
        );
        assert!(
            !html.contains("max-w-md"),
            "the fixed narrow-column cap is removed"
        );
        assert!(html.contains(">Identity<") && html.contains(">Presentation<"));
        for f in [
            "name=\"name\"",
            "name=\"slug\"",
            "name=\"display_name\"",
            "name=\"description\"",
            "name=\"icon_url\"",
            "name=\"sort_order\"",
        ] {
            assert!(html.contains(f), "field {f} preserved after regrouping");
        }
    }
}

#[cfg(test)]
mod stripe_admin_tests {
    // BUNYIP-416: unit coverage for the ported Products/Prices sections. The
    // live product/price listing is exercised against Stripe by the bunyip-api
    // integration tests (this port calls those existing endpoints); here we
    // cover the rendering + the dollars->cents parsing, including the $0.00
    // lifetime-price case that must render as a real price, not "--".
    use super::{parse_price_cents, stripe_prices_block, stripe_products_block, WebhookRetry};
    use crate::api::types::{StripePrice, StripeProduct};
    use crate::api::ApiError;
    use crate::util::format_stripe_amount;

    fn product(id: &str, name: &str, active: bool) -> StripeProduct {
        StripeProduct {
            id: id.into(),
            name: name.into(),
            description: Some("desc".into()),
            active,
            created: 0,
            member_count: 0,
        }
    }
    fn product_with_members(id: &str, name: &str, member_count: i64) -> StripeProduct {
        StripeProduct {
            member_count,
            ..product(id, name, true)
        }
    }
    fn price(id: &str, product_id: &str, amount: Option<i64>, active: bool) -> StripePrice {
        StripePrice {
            id: id.into(),
            product_id: product_id.into(),
            unit_amount: amount,
            currency: "usd".into(),
            recurring_interval: Some("month".into()),
            active,
            member_count: 0,
        }
    }
    fn price_with_members(id: &str, product_id: &str, member_count: i64) -> StripePrice {
        StripePrice {
            member_count,
            ..price(id, product_id, Some(300), true)
        }
    }

    /// A generic 500 from bunyip-api: `user_message` collapses it (BUNYIP-477),
    /// so the block itself has to name the likely cause.
    fn load_error() -> ApiError {
        ApiError {
            status: 500,
            code: "INTERNAL_ERROR".into(),
            message: "Failed to list webhook endpoints".into(),
            retry_after: None,
            request_id: Some("req_abc123".into()),
        }
    }

    /// The 400 `stripe_err_for` produces for `more_permissions_required`: the
    /// message is bunyip-authored and names the permission, so it passes through.
    fn permission_error(permission: &str) -> ApiError {
        ApiError {
            status: 400,
            code: "VALIDATION_ERROR".into(),
            message: format!(
                "Your Stripe restricted key does not have the {permission} permission. Add Write access for {permission} to the key in the Stripe dashboard, paste the key into Secret key above, and save."
            ),
            retry_after: None,
            request_id: Some("req_perm001".into()),
        }
    }

    #[test]
    fn format_stripe_amount_handles_zero_and_null() {
        assert_eq!(format_stripe_amount(Some(0), "usd"), "$0.00");
        assert_eq!(format_stripe_amount(Some(999), "usd"), "$9.99");
        assert_eq!(format_stripe_amount(Some(1000), "eur"), "€10.00");
        assert_eq!(format_stripe_amount(Some(500), "gbp"), "£5.00");
        assert_eq!(format_stripe_amount(Some(1234), "aud"), "12.34 AUD");
        assert_eq!(format_stripe_amount(None, "usd"), "--");
    }

    #[test]
    fn parse_price_cents_allows_zero_rejects_bad() {
        assert_eq!(parse_price_cents("0"), Ok(0)); // lifetime plan
        assert_eq!(parse_price_cents("9.99"), Ok(999));
        assert_eq!(parse_price_cents(" 10 "), Ok(1000));
        assert!(parse_price_cents("-1").is_err());
        assert!(parse_price_cents("").is_err());
        assert!(parse_price_cents("abc").is_err());
    }

    #[test]
    fn products_block_lists_and_gates_archive() {
        let list = [
            product("prod_a", "Personal Plan", true),
            product("prod_b", "Old Plan", false),
        ];
        // Each active product has an active price, so no "no active price" warning.
        let prices = [price("price_a", "prod_a", Some(300), true)];
        let html = stripe_products_block(Ok(&list), Ok(&prices)).into_string();
        assert!(html.contains("Personal Plan") && html.contains("Old Plan"));
        assert!(html.contains(">Active<") && html.contains(">Archived<"));
        // Create form present; archive only for the active product.
        assert!(html.contains(r#"action="/admin/stripe/products""#));
        assert!(html.contains(r#"action="/admin/stripe/products/prod_a/archive""#));
        assert!(
            !html.contains("prod_b/archive"),
            "archived product has no Archive action"
        );
        // Confirm text states the prices go too (BUNYIP-512).
        assert!(
            html.contains("Its prices are archived too"),
            "product archive confirmation says prices are archived as well"
        );
    }

    #[test]
    fn products_block_renders_load_error_state() {
        let html = stripe_products_block(Err(&load_error()), Ok(&[])).into_string();
        assert!(html.contains("Could not read the products from Stripe"));
    }

    // BUNYIP-512: a product whose plan has members shows a disabled Archive
    // control plus the count instead of a live archive form.
    #[test]
    fn products_block_gates_archive_when_members_present() {
        let list = [product_with_members("prod_busy", "Busy Plan", 3)];
        let prices = [price("price_busy", "prod_busy", Some(300), true)];
        let html = stripe_products_block(Ok(&list), Ok(&prices)).into_string();
        assert!(html.contains("3 members"), "member count shown");
        assert!(html.contains("disabled"), "archive control is disabled");
        assert!(
            !html.contains("prod_busy/archive"),
            "no live archive form while members are on the plan"
        );
    }

    // BUNYIP-512: singular vs plural on the courtesy label.
    #[test]
    fn products_block_member_count_is_singular_for_one() {
        let list = [product_with_members("prod_one", "Solo Plan", 1)];
        let html = stripe_products_block(Ok(&list), Ok(&[])).into_string();
        assert!(html.contains("1 member"), "singular label");
        assert!(!html.contains("1 members"), "no stray plural");
    }

    // BUNYIP-512: an active product with no active price is flagged.
    #[test]
    fn products_block_flags_active_product_without_active_price() {
        let list = [product("prod_empty", "Empty Plan", true)];
        // Only an archived price exists for it.
        let prices = [price("price_dead", "prod_empty", Some(300), false)];
        let html = stripe_products_block(Ok(&list), Ok(&prices)).into_string();
        assert!(
            html.contains("No active price"),
            "unsellable active product is warned about"
        );
    }

    // BUNYIP-512: with prices unknown (load error) make no unsellable claim.
    #[test]
    fn products_block_no_warning_when_prices_unknown() {
        let list = [product("prod_x", "Plan X", true)];
        let html = stripe_products_block(Ok(&list), Err(&load_error())).into_string();
        assert!(
            !html.contains("No active price"),
            "cannot claim unsellable when the price list failed to load"
        );
    }

    #[test]
    fn prices_block_shows_zero_price_and_resolves_product_name() {
        let products = [product("prod_life", "Lifetime", true)];
        let prices = [price("price_free", "prod_life", Some(0), true)];
        let html = stripe_prices_block(Ok(&prices), Ok(&products)).into_string();
        assert!(
            html.contains("$0.00"),
            "zero lifetime price renders as $0.00, not --"
        );
        assert!(html.contains("Lifetime"), "product name resolved from id");
        assert!(
            html.contains(r#"action="/admin/stripe/prices""#),
            "create form present"
        );
        assert!(html.contains(r#"action="/admin/stripe/prices/price_free/archive""#));
    }

    // BUNYIP-512: a price whose plan has members shows the disabled control +
    // count, not a live archive form.
    #[test]
    fn prices_block_gates_archive_when_members_present() {
        let products = [product("prod_std", "Standard", true)];
        let prices = [price_with_members("price_std", "prod_std", 5)];
        let html = stripe_prices_block(Ok(&prices), Ok(&products)).into_string();
        assert!(
            html.contains("5 members"),
            "member count shown on the price row"
        );
        assert!(html.contains("disabled"), "archive control disabled");
        assert!(
            !html.contains("price_std/archive"),
            "no live archive form while the price's plan has members"
        );
    }

    // BUNYIP-513: an archived product row offers Unarchive; an active row does not.
    #[test]
    fn products_block_offers_unarchive_for_archived_only() {
        let list = [
            product("prod_active", "Active Plan", true),
            product("prod_gone", "Archived Plan", false),
        ];
        let html = stripe_products_block(Ok(&list), Ok(&[])).into_string();
        assert!(
            html.contains(r#"action="/admin/stripe/products/prod_gone/unarchive""#),
            "archived product has an Unarchive control"
        );
        assert!(html.contains("Unarchive"), "Unarchive label present");
        assert!(
            !html.contains("prod_active/unarchive"),
            "active product has no Unarchive control"
        );
        assert!(
            !html.contains("prod_gone/archive"),
            "archived product has no Archive control"
        );
        // Confirm copy states it becomes purchasable again (AC).
        assert!(
            html.contains("becomes purchasable again"),
            "unarchive confirmation states the plan becomes purchasable again"
        );
    }

    // BUNYIP-513: same for prices.
    #[test]
    fn prices_block_offers_unarchive_for_archived_only() {
        let products = [product("prod_x", "X", true)];
        let prices = [
            price("price_live", "prod_x", Some(300), true),
            price("price_gone", "prod_x", Some(300), false),
        ];
        let html = stripe_prices_block(Ok(&prices), Ok(&products)).into_string();
        assert!(
            html.contains(r#"action="/admin/stripe/prices/price_gone/unarchive""#),
            "archived price has an Unarchive control"
        );
        assert!(
            !html.contains("price_live/unarchive"),
            "active price has no Unarchive control"
        );
        assert!(
            !html.contains("price_gone/archive"),
            "archived price has no Archive control"
        );
    }

    #[test]
    fn catalog_section_asks_for_price_only_and_shows_derived_product() {
        // BUNYIP-517: the catalog form asks for a price per tier (as a select)
        // and no longer asks for a product id; the product is shown read-only,
        // derived from the mapped price.
        let tier: crate::api::types::TierConfigResponse =
            serde_json::from_value(serde_json::json!({
                "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
                "standard_trial_days": 30,
                "free_price_id": "price_free123", "early_adopter_price_id": null,
                "standard_price_id": null, "lifetime_product_id": "prod_life123",
                "source": "database", "lifetime_slots_used": 0, "early_adopter_slots_used": 0
            }))
            .unwrap();
        // The mapped free price resolves to the same product that is stored, so
        // no disagreement flag.
        let prices = [price("price_free123", "prod_life123", Some(0), true)];
        let html = super::stripe_catalog_section(Ok(&tier), Some(&prices), Err("unavailable"))
            .into_string();
        assert!(
            html.contains(r#"action="/admin/stripe/catalog""#),
            "catalog form present"
        );
        // Price fields are present as selects; product id inputs are gone.
        for f in [
            "free_price_id",
            "early_adopter_price_id",
            "standard_price_id",
        ] {
            assert!(html.contains(f), "price field {f} present");
        }
        for gone in [
            r#"name="lifetime_product_id""#,
            r#"name="standard_product_id""#,
            r#"name="early_adopter_product_id""#,
        ] {
            assert!(!html.contains(gone), "product id input {gone} must be gone");
        }
        // The stored price is preselected and its derived product shown.
        assert!(html.contains("price_free123"), "current price preselected");
        assert!(html.contains("prod_life123"), "derived product shown");
        assert!(
            !html.contains("Stored product differs"),
            "no disagreement when stored product matches the price's product"
        );
        // Load-error state when the tier config is unavailable.
        assert!(
            super::stripe_catalog_section(Err(&load_error()), None, Err("unavailable"))
                .into_string()
                .contains("Could not load the tier catalog mapping")
        );
    }

    #[test]
    fn catalog_section_flags_a_stored_product_that_disagrees_with_the_price() {
        // BUNYIP-517: a stored product id that no longer matches the mapped
        // price's product is flagged, not silently rewritten.
        let tier: crate::api::types::TierConfigResponse =
            serde_json::from_value(serde_json::json!({
                "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
                "standard_trial_days": 30,
                "free_price_id": null, "early_adopter_price_id": null,
                "standard_price_id": "price_std", "standard_product_id": "prod_STALE",
                "source": "database", "lifetime_slots_used": 0, "early_adopter_slots_used": 0
            }))
            .unwrap();
        // The mapped standard price actually belongs to a different product.
        let prices = [price("price_std", "prod_REAL", Some(300), true)];
        let html = super::stripe_catalog_section(Ok(&tier), Some(&prices), Err("unavailable"))
            .into_string();
        assert!(
            html.contains("Stored product differs"),
            "disagreement is flagged"
        );
        assert!(
            html.contains("prod_STALE"),
            "the stale stored product is named"
        );
    }

    // BUNYIP-510: the webhook block must show the real endpoint URL (the route
    // is mounted under /v1), say which way the data flows, say whether
    // processing is live, and stop instructing a paste the api already did.
    use super::{
        is_public_https_origin, stripe_webhook_url, stripe_webhooks_block, webhook_created_page,
    };
    use crate::api::types::StripeWebhookEndpoint;

    fn endpoint(secret: Option<&str>) -> StripeWebhookEndpoint {
        StripeWebhookEndpoint {
            id: "we_123".into(),
            url: "https://api.example.com/v1/webhooks/stripe".into(),
            enabled_events: vec!["checkout.session.completed".into()],
            status: "enabled".into(),
            secret: secret.map(str::to_string),
        }
    }

    #[test]
    fn webhook_url_is_the_v1_path_and_never_doubles_the_slash() {
        assert_eq!(
            stripe_webhook_url("https://api.example.com"),
            "https://api.example.com/v1/webhooks/stripe"
        );
        assert_eq!(
            stripe_webhook_url("https://api.example.com/"),
            "https://api.example.com/v1/webhooks/stripe"
        );
        assert!(stripe_webhook_url("http://api:4401").ends_with("/v1/webhooks/stripe"));
        assert!(!stripe_webhook_url("https://api.example.com//").contains("com//"));
    }

    #[test]
    fn only_a_public_https_origin_passes_the_caption_check() {
        assert!(is_public_https_origin("https://api.example.com"));
        assert!(is_public_https_origin("https://api.example.com:8443"));
        // The `api_url` fallback shapes: internal Docker host, plain http, loopback.
        assert!(!is_public_https_origin("http://api:4401"));
        assert!(!is_public_https_origin("http://localhost:4401"));
        assert!(!is_public_https_origin("https://localhost:4401"));
        assert!(!is_public_https_origin("https://127.0.0.1"));
        assert!(!is_public_https_origin("https://[::1]:4401"));
        assert!(!is_public_https_origin(""));
    }

    #[test]
    fn webhooks_block_prefills_the_derived_url_and_names_its_source() {
        let html = stripe_webhooks_block(
            Ok(&[]),
            "https://api.example.com",
            true,
            &WebhookRetry::default(),
        )
        .into_string();
        assert!(
            html.contains(r#"value="https://api.example.com/v1/webhooks/stripe""#),
            "endpoint URL prefilled with the real path"
        );
        assert!(
            html.contains(r#"placeholder="https://api.example.com/v1/webhooks/stripe""#),
            "placeholder carries /v1 too"
        );
        assert!(html.contains("BUNYIP_API_PUBLIC_ORIGIN"), "source named");
        assert!(
            !html.contains("text-destructive-text"),
            "a public https origin renders the plain caption, not the warning"
        );
        // Direction + purpose are explicit, and the empty state matches.
        assert!(html.contains("Receives information from Stripe"));
        assert!(html.contains("grant or revoke product entitlements"));
        assert!(html.contains("so Stripe can send checkout, subscription, and payment events"));
    }

    #[test]
    fn webhooks_block_warns_when_the_origin_is_not_public() {
        let html =
            stripe_webhooks_block(Ok(&[]), "http://api:4401", true, &WebhookRetry::default())
                .into_string();
        assert!(
            html.contains(r#"value="http://api:4401/v1/webhooks/stripe""#),
            "still prefilled, but flagged"
        );
        assert!(
            html.contains("text-destructive-text") && html.contains("Set BUNYIP_API_PUBLIC_ORIGIN"),
            "caption warns and names the variable to set"
        );
    }

    #[test]
    fn webhooks_block_states_whether_processing_is_active() {
        let live = stripe_webhooks_block(
            Ok(&[]),
            "https://api.example.com",
            true,
            &WebhookRetry::default(),
        )
        .into_string();
        assert!(live.contains("Webhook processing is active"));
        assert!(!live.contains("rejects every incoming Stripe event"));

        let off = stripe_webhooks_block(
            Ok(&[]),
            "https://api.example.com",
            false,
            &WebhookRetry::default(),
        )
        .into_string();
        assert!(off.contains("Webhook processing is not active"));
        assert!(
            off.contains("rejects every incoming Stripe event until a signing secret is saved"),
            "matches what stripe_webhook actually does (BUNYIP-203)"
        );
    }

    #[test]
    fn webhooks_block_never_asks_for_a_manual_paste() {
        let html = stripe_webhooks_block(
            Ok(&[]),
            "https://api.example.com",
            false,
            &WebhookRetry::default(),
        )
        .into_string();
        let lower = html.to_lowercase();
        assert!(
            !lower.contains("paste") && !lower.contains("copy"),
            "the api saves the signing secret itself; no manual step to advertise"
        );
    }

    // ---- BUNYIP-516 -------------------------------------------------------
    // A list bunyip could not read must never render as "none exist", and the
    // reason it could not read it has to be on the page, not only in the log.

    /// The three Stripe-backed blocks each keep "could not read" and "there are
    /// none" apart, name the permission that usually explains the former, and
    /// carry the api request id that locates it in the log.
    #[test]
    fn every_stripe_block_separates_could_not_read_from_empty() {
        let cases: [(&str, &str, String, String); 3] = [
            (
                "products",
                "Products",
                stripe_products_block(Err(&load_error()), Ok(&[])).into_string(),
                stripe_products_block(Ok(&[]), Ok(&[])).into_string(),
            ),
            (
                "prices",
                "Prices",
                stripe_prices_block(Err(&load_error()), Ok(&[])).into_string(),
                stripe_prices_block(Ok(&[]), Ok(&[])).into_string(),
            ),
            (
                "webhook endpoints",
                "Webhook Endpoints",
                stripe_webhooks_block(
                    Err(&load_error()),
                    "https://api.example.com",
                    true,
                    &WebhookRetry::default(),
                )
                .into_string(),
                stripe_webhooks_block(
                    Ok(&[]),
                    "https://api.example.com",
                    true,
                    &WebhookRetry::default(),
                )
                .into_string(),
            ),
        ];

        for (noun, permission, unreadable, empty) in cases {
            assert!(
                unreadable.contains(&format!("Could not read the {noun} from Stripe")),
                "{noun}: the failure says what could not be read: {unreadable}"
            );
            assert!(
                unreadable.contains("cannot tell whether"),
                "{noun}: the failure admits bunyip does not know: {unreadable}"
            );
            assert!(
                unreadable.contains(&format!("lacks the {permission} permission")),
                "{noun}: the likely cause names the permission: {unreadable}"
            );
            assert!(
                unreadable.contains("req_abc123"),
                "{noun}: the api request id ties it to the log: {unreadable}"
            );
            // The whole point: the unreadable state must NOT read as "none".
            assert!(
                !unreadable.contains("No products yet")
                    && !unreadable.contains("No prices yet")
                    && !unreadable.contains("No webhook endpoints yet"),
                "{noun}: an unreadable list never renders the empty state: {unreadable}"
            );
            // ...and a genuinely empty list still does, with no error text.
            assert!(
                empty.contains("yet.") && !empty.contains("Could not read"),
                "{noun}: a real empty list keeps the empty state: {empty}"
            );
        }
    }

    /// An unreadable product list must not leave the Prices form's picker
    /// looking like an account with no products.
    #[test]
    fn an_unreadable_product_list_explains_the_empty_picker() {
        let html = stripe_prices_block(Ok(&[]), Err(&load_error())).into_string();
        assert!(
            html.contains("Empty because the products could not be read from Stripe"),
            "the picker says why it is empty: {html}"
        );
        // A readable-but-empty product list says nothing of the sort.
        let clean = stripe_prices_block(Ok(&[]), Ok(&[])).into_string();
        assert!(!clean.contains("could not be read from Stripe"));
    }

    /// When bunyip-api already answered with the authored 4xx naming the exact
    /// permission, that message is what the block shows, verbatim.
    #[test]
    fn a_permission_failure_reaches_the_page_verbatim() {
        let html = stripe_webhooks_block(
            Err(&permission_error("Webhook Endpoints")),
            "https://api.example.com",
            true,
            &WebhookRetry::default(),
        )
        .into_string();
        assert!(
            html.contains("does not have the Webhook Endpoints permission"),
            "the API's authored 4xx copy is shown, not a generic line: {html}"
        );
        assert!(
            html.contains("paste the key into Secret key above, and save"),
            "the fix steps survive: {html}"
        );
        assert!(
            !html.contains("An unexpected error occurred"),
            "a 4xx is never collapsed to the generic line: {html}"
        );
        assert!(html.contains("req_perm001"), "reference present: {html}");
    }

    /// A failed create restates the reason next to the button and keeps what was
    /// typed, so retrying after fixing the key is one click.
    #[test]
    fn a_failed_create_redisplays_the_submitted_url_and_events() {
        let err = permission_error("Webhook Endpoints");
        let msg = err.user_message();
        let retry = WebhookRetry {
            error: Some(&msg),
            url: Some("https://custom.example.com/v1/webhooks/stripe"),
            events: Some("checkout.session.completed, invoice.payment_failed"),
            reference: err.request_id.as_deref(),
        };
        let html =
            stripe_webhooks_block(Ok(&[]), "https://api.example.com", true, &retry).into_string();

        assert!(
            html.contains("Creating the webhook endpoint failed"),
            "the failure is stated on the page, not only as a toast: {html}"
        );
        assert!(
            html.contains("does not have the Webhook Endpoints permission"),
            "the reason is the authored permission copy: {html}"
        );
        assert!(
            html.contains(r#"value="https://custom.example.com/v1/webhooks/stripe""#),
            "the submitted URL is redisplayed, not replaced by the derived one: {html}"
        );
        assert!(
            html.contains("checkout.session.completed, invoice.payment_failed"),
            "the submitted event list is redisplayed: {html}"
        );
        assert!(
            !html.contains("customer.subscription.created"),
            "the submitted events replace the defaults rather than reappending them: {html}"
        );
        assert!(html.contains("req_perm001"), "reference present: {html}");
    }

    /// A plain page load carries no retry state, so the form keeps its derived
    /// URL and recommended events and shows no failure box.
    #[test]
    fn a_clean_load_keeps_the_derived_defaults() {
        let html = stripe_webhooks_block(
            Ok(&[]),
            "https://api.example.com",
            true,
            &WebhookRetry::default(),
        )
        .into_string();
        assert!(html.contains(r#"value="https://api.example.com/v1/webhooks/stripe""#));
        assert!(html.contains("customer.subscription.created"));
        assert!(!html.contains("Creating the webhook endpoint failed"));
    }

    /// The setup docs must ask for the permission the page's own Create endpoint
    /// button needs; asking for the other five and not this one is what produced
    /// the unresolvable 403.
    #[test]
    fn setup_docs_ask_for_the_webhook_endpoints_permission() {
        let html = super::stripe_setup_docs().into_string();
        for permission in [
            "Products",
            "Prices",
            "Customers",
            "Subscriptions",
            "Checkout Sessions",
            "Webhook Endpoints",
        ] {
            assert!(
                html.contains(permission),
                "the Write list names {permission}: {html}"
            );
        }
        assert!(html.contains("Invoices"), "Read list unchanged");
        assert!(
            html.contains("Create endpoint"),
            "the docs tie the permission to the button that needs it: {html}"
        );
    }

    #[test]
    fn created_page_reports_the_auto_save_and_only_the_none_branch_asks_for_a_paste() {
        let saved = webhook_created_page(&endpoint(Some("whsec_abc123"))).into_string();
        assert!(saved.contains("whsec_abc123"), "secret still shown once");
        assert!(saved.contains("saved the signing secret automatically"));
        let lower = saved.to_lowercase();
        assert!(
            !lower.contains("paste") && !lower.contains("copy"),
            "success branch instructs no manual step"
        );

        let missing = webhook_created_page(&endpoint(None)).into_string();
        assert!(missing.contains("Stripe did not return a signing secret"));
        assert!(
            missing.contains("rejects every incoming Stripe event until one is saved"),
            "None branch states the consequence"
        );
        assert!(
            missing.contains("paste it into Webhook secret"),
            "None branch keeps the manual instruction"
        );
    }
}

/// BUNYIP-421: the users-list identity cell must ellipsise a long email without
/// clipping the role/status badges that sit beside it.
#[cfg(test)]
mod identity_cell_clipping_tests {
    use crate::api::types::{AdminUser, MembershipStatus, MembershipTier, UserRole};
    use crate::views::ui::assert_no_truncating_flex_container;

    fn user(role: UserRole, suspended: bool) -> AdminUser {
        AdminUser {
            id: "u1".into(),
            email: "person.with.a.very.long.email.address@example.com".into(),
            role,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::Active,
            membership_tier: MembershipTier::EarlyAdopter,
            lifetime_member: false,
            created_at: "2026-03-04T10:00:00Z".into(),
            last_login_at: None,
            grace_period_end: None,
            suspended,
        }
    }

    #[test]
    fn badges_survive_a_long_email() {
        let row = super::user_grid_row(&user(UserRole::Admin, false)).into_string();
        // The clip was invisible in the markup: the badge WAS emitted, the row's
        // own `overflow:hidden` just painted none of it. Guard the CSS shape.
        assert_no_truncating_flex_container(&row);
        assert!(row.contains(">Admin<"), "admin badge is rendered");
        assert!(
            row.contains(
                r#"<span class="truncate">person.with.a.very.long.email.address@example.com</span>"#
            ),
            "the email, not the row, is what truncates: {row}"
        );

        let suspended = super::user_grid_row(&user(UserRole::Subscriber, true)).into_string();
        assert_no_truncating_flex_container(&suspended);
        assert!(
            suspended.contains(">Suspended<"),
            "suspended badge is rendered"
        );
    }
}

#[cfg(test)]
mod admin_action_confirm_tests {
    //! BUNYIP-430: every significant admin control routes through the one shared
    //! confirmation dialog (`data-confirm` + `assets/js/app.js`, which prompts
    //! on submit and cancels the POST when the admin declines), and each prompt
    //! names the action and the specific user (by email) it affects.
    use super::user_actions_card;
    use crate::api::types::{AdminUser, MembershipStatus, MembershipTier, UserRole};

    const UID: &str = "22222222-2222-2222-2222-222222222222";

    fn target(email: &str, lifetime_member: bool) -> AdminUser {
        AdminUser {
            id: UID.into(),
            email: email.into(),
            role: UserRole::Subscriber,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::None,
            membership_tier: MembershipTier::Free,
            lifetime_member,
            created_at: String::new(),
            last_login_at: None,
            grace_period_end: None,
            suspended: false,
        }
    }

    // BUNYIP-431 replaced the Grant/Revoke lifetime buttons in this card with the
    // 2FA-gated tier selector (`tier_change_card`, covered in `tier_change_tests`),
    // so the lifetime-specific confirm tests moved out with them.

    #[test]
    fn reset_password_confirms_and_names_the_user() {
        let html = user_actions_card(&target("jane@example.com", false), false).into_string();
        assert!(
            html.contains("Send a password reset email to jane@example.com?"),
            "reset-password confirms and names the user: {html}"
        );
    }

    #[test]
    fn role_change_shares_the_component_and_names_the_user() {
        // BUNYIP-109 control (Make Admin / Demote) now routes through the same
        // shared dialog and names the user, per BUNYIP-430 AC 3.
        let html = user_actions_card(&target("jane@example.com", false), false).into_string();
        assert!(
            html.contains("Change jane@example.com's role to admin?")
                || html.contains("Change jane@example.com&#39;s role to admin?"),
            "role change confirms and names the user: {html}"
        );
    }

    #[test]
    fn every_action_form_is_gated_by_the_shared_confirm() {
        // Cancelling the shared dialog (app.js) blocks the POST, so state is left
        // unchanged (AC 5). Guard that no state-changing control in the card
        // ships without data-confirm, for a lifetime and a non-lifetime user.
        for lifetime in [false, true] {
            let html = user_actions_card(&target("jane@example.com", lifetime), true).into_string();
            let forms = html.matches("<form").count();
            let confirms = html.matches("data-confirm=").count();
            assert!(
                forms > 0 && forms == confirms,
                "every action form ({forms}) carries data-confirm ({confirms}): {html}"
            );
        }
    }
}

#[cfg(test)]
mod tier_change_tests {
    //! BUNYIP-431: the tier selector offers every configured tier regardless of
    //! the member's current tier (any-to-any), and applying a change requires
    //! the acting admin's 2FA code.
    use super::tier_change_card;
    use crate::api::types::{AdminUser, MembershipStatus, MembershipTier, UserRole};

    const UID: &str = "33333333-3333-3333-3333-333333333333";

    fn target(tier: MembershipTier) -> AdminUser {
        AdminUser {
            id: UID.into(),
            email: "jane@example.com".into(),
            role: UserRole::Subscriber,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::None,
            membership_tier: tier,
            lifetime_member: false,
            created_at: String::new(),
            last_login_at: None,
            grace_period_end: None,
            suspended: false,
        }
    }

    #[test]
    fn offers_every_tier_regardless_of_current() {
        // AC3: the options do not vary with the member's current tier - whatever
        // they hold, all four destinations are offered (including downgrades).
        for current in [
            MembershipTier::Lifetime,
            MembershipTier::EarlyAdopter,
            MembershipTier::Standard,
            MembershipTier::Free,
        ] {
            let html = tier_change_card(&target(current)).into_string();
            for value in ["lifetime", "early_adopter", "standard", "free"] {
                assert!(
                    html.contains(&format!(r#"value="{value}""#)),
                    "tier option {value} is offered regardless of current tier"
                );
            }
        }
    }

    #[test]
    fn requires_a_2fa_code_and_posts_to_the_tier_route() {
        let html = tier_change_card(&target(MembershipTier::Standard)).into_string();
        assert!(html.contains(&format!(r#"action="/admin/users/{UID}/tier""#)));
        assert!(
            html.contains(r#"name="totp_code""#) && html.contains("required"),
            "the admin's 2FA code is a required field: {html}"
        );
    }

    #[test]
    fn preselects_the_current_tier() {
        let html = tier_change_card(&target(MembershipTier::EarlyAdopter)).into_string();
        assert!(
            html.contains(r#"value="early_adopter" selected"#),
            "the member's current tier is preselected: {html}"
        );
    }
}

#[cfg(test)]
mod rate_limit_management_tests {
    //! BUNYIP-413: the management controls are super-admin-only. The API
    //! enforces that too, so these assert the UI does not offer a control the
    //! caller's write would be refused for.
    use super::*;

    fn cfg(action: &str, overridden: bool) -> AdminRateLimitConfig {
        AdminRateLimitConfig {
            action: action.to_string(),
            max_requests: if overridden { 25 } else { 5 },
            window_seconds: 60,
            default_max_requests: 5,
            default_window_seconds: 60,
            overridden,
            updated_at: None,
        }
    }

    #[test]
    fn config_card_offers_edit_and_revert_to_the_super_admin() {
        let html = rate_limit_config_card(&[cfg("login", true)], true, true).into_string();
        assert!(
            html.contains(r#"action="/admin/rate-limits/config""#),
            "the save form is rendered"
        );
        assert!(
            html.contains(r#"action="/admin/rate-limits/config/reset""#),
            "an overridden limit offers a revert"
        );
        assert!(
            html.contains(r#"name="max_requests""#) && html.contains(r#"name="window_seconds""#)
        );
    }

    #[test]
    fn config_card_is_read_only_for_an_ordinary_admin() {
        let html = rate_limit_config_card(&[cfg("login", true)], true, false).into_string();
        assert!(
            !html.contains("/admin/rate-limits/config"),
            "no management form for a non-super-admin"
        );
        assert!(
            html.contains("Only the super admin can change them."),
            "the read-only card says why"
        );
        // The numbers are still visible, so the screen stays informative.
        assert!(html.contains("Login"));
    }

    #[test]
    fn a_limit_on_its_default_offers_no_revert() {
        let html = rate_limit_config_card(&[cfg("login", false)], true, true).into_string();
        assert!(html.contains(r#"action="/admin/rate-limits/config""#));
        assert!(
            !html.contains("/admin/rate-limits/config/reset"),
            "nothing to revert when no override is in force"
        );
    }

    #[test]
    fn ban_add_card_posts_ip_reason_and_duration() {
        let html = ip_ban_add_card(None).into_string();
        assert!(html.contains(r#"action="/admin/ip-bans/add""#));
        assert!(html.contains(r#"name="ip""#));
        assert!(html.contains(r#"name="reason""#));
        assert!(html.contains(r#"name="duration_secs""#));
    }

    /// BUNYIP-436: a "Ban this address" link carries the IP as `?ip=`, and the
    /// add-ban form seeds its address field from it so the admin lands ready to
    /// submit. An empty prefill leaves the field blank.
    #[test]
    fn ban_add_card_prefills_ip_from_query() {
        let html = ip_ban_add_card(Some("203.0.113.7")).into_string();
        assert!(
            html.contains(r#"name="ip""#) && html.contains(r#"value="203.0.113.7""#),
            "add-ban form seeds the address field from the prefill"
        );
        let blank = ip_ban_add_card(None).into_string();
        assert!(
            blank.contains(r#"value="""#) || !blank.contains("value="),
            "no prefill leaves the address field empty"
        );
    }

    /// BUNYIP-436: the captured IP on the feedback detail links into the ban
    /// flow (the ip-bans page prefills its add form from `?ip=`), while the
    /// user agent is shown as plain admin-only text. The address is
    /// URL-encoded into the query.
    #[test]
    fn feedback_detail_links_ip_into_ban_flow() {
        let detail = AdminFeedbackDetail {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            name: Some("Ada".to_string()),
            email: None,
            email_masked: None,
            subject: Some("Broken button".to_string()),
            tags: vec![],
            message: "It does not work".to_string(),
            page_path: None,
            status: FeedbackStatus::New,
            admin_response: None,
            created_at: "2026-08-01T00:00:00Z".to_string(),
            responded_at: None,
            attachments: vec![],
            submitter_ip: Some("203.0.113.7".to_string()),
            user_agent: Some("Mozilla/5.0 Firefox/121.0".to_string()),
        };
        let html = super::feedback_detail_view(&detail, super::FeedbackTab::Spam).into_string();
        assert!(
            html.contains(r#"href="/admin/ip-bans?ip=203.0.113.7""#),
            "the IP links into the ip-bans add flow"
        );
        assert!(
            html.contains("Mozilla/5.0 Firefox/121.0"),
            "user agent shown"
        );
    }

    #[test]
    fn window_labels_are_compact() {
        assert_eq!(fmt_window_secs(45), "45s");
        assert_eq!(fmt_window_secs(60), "1m");
        assert_eq!(fmt_window_secs(900), "15m");
        assert_eq!(fmt_window_secs(3600), "1h");
    }
}
