//! Admin panel route table.
//!
//! DEV-517: lifted out of `main.rs` so the panel's routing lives next to its
//! handlers, the way a8n-tools splits `routes/` from `handlers/`.

use axum::routing::{get, post};
use axum::Router;

use crate::handlers::admin;
use crate::web::AppState;

/// Every route the admin panel owns, merged into the app router by `main`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin::dashboard))
        .route("/admin/audit-logs", get(admin::audit_logs))
        .route("/admin/logs", get(admin::logs))
        .route("/admin/seed", get(admin::seed_data))
        .route("/admin/seed/export", get(admin::seed_export))
        .route("/admin/seed/import", post(admin::seed_import))
        .route("/admin/seed/template", post(admin::seed_load_template))
        .route("/admin/ip-bans", get(admin::ip_bans))
        .route("/admin/ip-bans/add", post(admin::ip_ban_create))
        .route("/admin/ip-bans/unban", post(admin::ip_unban))
        .route("/admin/rate-limits", get(admin::rate_limits))
        .route("/admin/rate-limits/reset", post(admin::rate_limit_reset))
        .route(
            "/admin/rate-limits/config",
            post(admin::rate_limit_config_save),
        )
        .route(
            "/admin/rate-limits/config/reset",
            post(admin::rate_limit_config_reset),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/:id", get(admin::user_detail))
        .route("/admin/users/:id/role", post(admin::user_role))
        .route("/admin/users/:id/email", post(admin::user_email))
        .route(
            "/admin/users/:id/email/verify",
            post(admin::user_verify_email),
        )
        .route(
            "/admin/users/:id/two-factor/reset",
            post(admin::user_reset_2fa),
        )
        .route("/admin/users/:id/delete", post(admin::user_delete))
        .route("/admin/users/:id/suspend", post(admin::user_suspend))
        .route("/admin/users/:id/reactivate", post(admin::user_reactivate))
        .route(
            "/admin/users/:id/reset-password",
            post(admin::user_reset_password),
        )
        .route(
            "/admin/users/:id/lifetime",
            post(admin::user_grant_lifetime),
        )
        .route(
            "/admin/users/:id/lifetime/revoke",
            post(admin::user_revoke_lifetime),
        )
        .route("/admin/users/:id/tier", post(admin::user_set_tier))
        .route("/admin/memberships", get(admin::memberships))
        .route(
            "/admin/memberships/:user_id/grant",
            post(admin::membership_grant),
        )
        .route(
            "/admin/memberships/:user_id/revoke",
            post(admin::membership_revoke),
        )
        .route("/admin/feedback", get(admin::feedback))
        .route("/admin/feedback/export", get(admin::feedback_export))
        // Tab + archive routes register BEFORE the `:id` detail route so
        // axum's matcher does not interpret the literal `closed` / `spam`
        // / `archive` as a feedback id.
        .route("/admin/feedback/closed", get(admin::feedback_closed))
        .route("/admin/feedback/spam", get(admin::feedback_spam))
        .route("/admin/feedback/archive", get(admin::feedback_archive))
        .route(
            "/admin/feedback/archive/:archive_id/restore",
            post(admin::feedback_restore),
        )
        .route("/admin/feedback/:id", get(admin::feedback_detail))
        .route("/admin/feedback/:id/respond", post(admin::feedback_respond))
        .route(
            "/admin/feedback/:id/attachments/:attachment_id",
            get(admin::feedback_attachment),
        )
        .route("/admin/feedback/:id/status", post(admin::feedback_status))
        .route(
            "/admin/feedback/:id/mark-spam",
            post(admin::feedback_mark_spam),
        )
        .route(
            "/admin/feedback/:id/unmark-spam",
            post(admin::feedback_unmark_spam),
        )
        .route(
            "/admin/feedback/:id/archive",
            post(admin::feedback_archive_action),
        )
        .route("/admin/feedback/:id/delete", post(admin::feedback_delete))
        .route(
            "/admin/applications",
            get(admin::applications).post(admin::application_create),
        )
        .route("/admin/applications/new", get(admin::application_new))
        .route("/admin/applications/:id/edit", get(admin::application_edit))
        .route(
            "/admin/applications/:id/distribution",
            post(admin::application_distribution_save),
        )
        .route(
            "/admin/applications/:id/delete",
            post(admin::application_delete),
        )
        .route(
            "/admin/applications/:id/field",
            post(admin::application_field),
        )
        .route(
            "/admin/applications/:id/group",
            post(admin::application_set_group),
        )
        .route(
            "/admin/applications/reorder",
            post(admin::application_reorder),
        )
        // BUNYIP-388: per-application documentation manager (admin authoring).
        .route(
            "/admin/applications/:id/docs",
            get(admin::application_docs).post(admin::application_doc_create),
        )
        .route(
            "/admin/applications/:id/docs/:doc_id",
            post(admin::application_doc_update),
        )
        .route(
            "/admin/applications/:id/docs/:doc_id/delete",
            post(admin::application_doc_delete),
        )
        // Application groups (BUNYIP-100)
        .route(
            "/admin/application-groups",
            get(admin::application_groups).post(admin::application_group_create),
        )
        .route(
            "/admin/application-groups/new",
            get(admin::application_group_new),
        )
        .route(
            "/admin/application-groups/:id/edit",
            get(admin::application_group_edit),
        )
        .route(
            "/admin/application-groups/:id",
            post(admin::application_group_save),
        )
        .route(
            "/admin/application-groups/:id/delete",
            post(admin::application_group_delete),
        )
        .route("/admin/entitlements", get(admin::entitlements))
        .route(
            "/admin/applications/:slug/restricted-toggle",
            post(admin::set_app_restricted),
        )
        .route(
            "/admin/users/:user_id/entitlements",
            get(admin::user_entitlements),
        )
        .route(
            "/admin/users/:user_id/entitlements/grant",
            post(admin::grant_user_entitlement_h),
        )
        .route(
            "/admin/users/:user_id/entitlements/revoke",
            post(admin::revoke_user_entitlement_h),
        )
        .route(
            "/admin/tier-settings",
            get(admin::tier_settings).post(admin::tier_settings_save),
        )
        .route("/admin/email", get(admin::email).post(admin::email_save))
        .route("/admin/email/test", post(admin::email_test))
        .route("/admin/email/test-send", post(admin::email_test_send))
        .route(
            "/admin/auto-ban-settings",
            get(admin::auto_ban_settings).post(admin::auto_ban_settings_save),
        )
        .route("/admin/stripe", get(admin::stripe).post(admin::stripe_save))
        // BUNYIP-416: Stripe product + price management (create + archive).
        // BUNYIP-513: plus the reverse (unarchive) for both.
        .route("/admin/stripe/products", post(admin::stripe_product_create))
        .route(
            "/admin/stripe/products/:id/archive",
            post(admin::stripe_product_archive),
        )
        .route(
            "/admin/stripe/products/:id/unarchive",
            post(admin::stripe_product_unarchive),
        )
        .route("/admin/stripe/prices", post(admin::stripe_price_create))
        .route(
            "/admin/stripe/prices/:id/archive",
            post(admin::stripe_price_archive),
        )
        .route(
            "/admin/stripe/prices/:id/unarchive",
            post(admin::stripe_price_unarchive),
        )
        // DEV-518: Stripe webhook-endpoint management (backend already existed).
        .route("/admin/stripe/webhooks", post(admin::stripe_webhook_create))
        .route(
            "/admin/stripe/webhooks/:id/delete",
            post(admin::stripe_webhook_delete),
        )
        // BUNYIP-417: tier -> Stripe price/product mapping moved from the Pricing tiers page.
        .route("/admin/stripe/catalog", post(admin::stripe_catalog_save))
        // BUNYIP-353: account backup & restore, reached from the Backup add-on
        // tile on /applications.
        .route("/integrations/backup", get(admin::backup_settings))
        .route("/integrations/backup/download", get(admin::backup_download))
        .route(
            "/integrations/backup/restore",
            post(admin::backup_restore).layer(
                // Raise the default axum 2 MB body limit for the restore upload;
                // the bundle embeds each entitled app's backup. Matches the
                // API's 8 MiB restore ceiling plus multipart overhead.
                axum::extract::DefaultBodyLimit::max(9 * 1024 * 1024),
            ),
        )
}
