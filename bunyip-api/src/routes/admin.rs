//! Admin routes

use actix_web::web;

use crate::handlers;

/// Configure admin routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            // Dashboard stats
            .route("/stats", web::get().to(handlers::get_dashboard_stats))
            // System health
            .route("/health", web::get().to(handlers::get_system_health))
            .route("/key-health", web::get().to(handlers::get_key_health))
            .route(
                "/key-health/{key_id}",
                web::get().to(handlers::get_key_health_by_id),
            )
            // User management
            .route("/users", web::get().to(handlers::list_users))
            .route("/users/{user_id}", web::get().to(handlers::get_user))
            .route("/users/{user_id}", web::delete().to(handlers::delete_user))
            .route(
                "/users/{user_id}/status",
                web::put().to(handlers::update_user_status),
            )
            .route(
                "/users/{user_id}/role",
                web::put().to(handlers::update_user_role),
            )
            .route(
                "/users/{user_id}/email",
                web::put().to(handlers::update_user_email),
            )
            .route(
                "/users/{user_id}/email/verify",
                web::post().to(handlers::verify_user_email),
            )
            .route(
                "/users/{user_id}/two-factor/reset",
                web::post().to(handlers::reset_user_two_factor),
            )
            .route(
                "/users/{user_id}/reset-password",
                web::post().to(handlers::admin_reset_password),
            )
            .route(
                "/users/{user_id}/impersonate",
                web::post().to(handlers::impersonate_user),
            )
            .route(
                "/users/{user_id}/lifetime",
                web::post().to(handlers::grant_lifetime_membership),
            )
            .route(
                "/users/{user_id}/lifetime/revoke",
                web::post().to(handlers::revoke_lifetime_membership),
            )
            // Per-product entitlements (BUNYIP-39)
            .route(
                "/users/{user_id}/entitlements",
                web::get().to(handlers::list_user_entitlements),
            )
            .route(
                "/users/{user_id}/entitlements",
                web::post().to(handlers::grant_entitlement),
            )
            .route(
                "/users/{user_id}/entitlements/revoke",
                web::post().to(handlers::revoke_entitlement),
            )
            .route(
                "/applications/{slug}/restricted",
                web::put().to(handlers::set_application_restricted),
            )
            .route(
                "/applications/{slug}/stripe-prices",
                web::post().to(handlers::add_price_mapping),
            )
            .route(
                "/applications/{slug}/stripe-prices",
                web::delete().to(handlers::remove_price_mapping),
            )
            // Membership management
            .route("/memberships", web::get().to(handlers::list_memberships))
            .route(
                "/memberships/grant",
                web::post().to(handlers::grant_membership),
            )
            .route(
                "/memberships/revoke",
                web::post().to(handlers::revoke_membership),
            )
            // Application management
            .route(
                "/applications",
                web::get().to(handlers::list_all_applications),
            )
            .route(
                "/applications",
                web::post().to(handlers::create_application),
            )
            .route(
                "/applications/{app_id}",
                web::put().to(handlers::update_application),
            )
            .route(
                "/applications/{app_id}/swap-order",
                web::put().to(handlers::swap_application_order),
            )
            .route(
                "/applications/{app_id}",
                web::delete().to(handlers::delete_application),
            )
            // BUNYIP-388: per-application documentation (admin authoring).
            .route(
                "/applications/{app_id}/docs",
                web::get().to(handlers::list_app_docs_admin),
            )
            .route(
                "/applications/{app_id}/docs",
                web::post().to(handlers::create_app_doc),
            )
            .route(
                "/application-docs/{doc_id}",
                web::put().to(handlers::update_app_doc),
            )
            .route(
                "/application-docs/{doc_id}",
                web::delete().to(handlers::delete_app_doc),
            )
            .route(
                "/applications/{app_id}/group",
                web::put().to(handlers::set_application_group),
            )
            // Application groups (BUNYIP-100)
            .route(
                "/application-groups",
                web::get().to(handlers::list_all_application_groups),
            )
            .route(
                "/application-groups",
                web::post().to(handlers::create_application_group),
            )
            .route(
                "/application-groups/{group_id}",
                web::put().to(handlers::update_application_group),
            )
            .route(
                "/application-groups/{group_id}",
                web::delete().to(handlers::delete_application_group),
            )
            .route(
                "/applications/{slug}/downloads/refresh",
                web::post().to(handlers::admin_refresh_release),
            )
            .route(
                "/applications/{slug}/oci/refresh",
                web::post().to(bunyip_oci::handlers::admin_oci::refresh_oci),
            )
            // Account-delete webhook replay (BUNYIP-211)
            .route(
                "/account-deletes/{user_id}/replay",
                web::post().to(handlers::replay_account_delete),
            )
            // IP auto-bans (BUNYIP-319)
            .route("/ip-bans", web::get().to(handlers::list_ip_bans))
            // Manual ban, super-admin only (BUNYIP-413)
            .route("/ip-bans", web::post().to(handlers::create_ip_ban))
            .route("/ip-bans/{ip}", web::delete().to(handlers::unban_ip))
            // Active rate limits (BUNYIP-315)
            .route("/rate-limits", web::get().to(handlers::list_rate_limits))
            // Reset an active rate limit (BUNYIP-316)
            .route(
                "/rate-limits/reset",
                web::post().to(handlers::reset_rate_limit),
            )
            // Rate-limit configuration: read for admins, write for the super
            // admin only (BUNYIP-413)
            .route(
                "/rate-limit-configs",
                web::get().to(handlers::list_rate_limit_configs),
            )
            .route(
                "/rate-limit-configs/{action}",
                web::put().to(handlers::upsert_rate_limit_config),
            )
            .route(
                "/rate-limit-configs/{action}",
                web::delete().to(handlers::delete_rate_limit_config),
            )
            // Audit logs
            .route("/audit-logs", web::get().to(handlers::list_audit_logs))
            // Error log ring buffer (BUNYIP-327)
            .route("/logs", web::get().to(handlers::get_error_logs))
            // Seed data import / export (PSA-52) + template library (PSA-57)
            .route(
                "/seed/templates",
                web::get().to(handlers::list_seed_templates),
            )
            .route("/seed/export", web::get().to(handlers::export_seed_data))
            // The import body is a whole seed file. Raise the payload cap well
            // above actix's 256 KiB `String`-extractor default - and above the
            // web BFF's 2 MiB form limit - so a large template is never
            // truncated at the API before the loader ever sees it.
            .service(
                web::resource("/seed/import")
                    .app_data(web::PayloadConfig::new(4 * 1024 * 1024))
                    .route(web::post().to(handlers::import_seed_data)),
            )
            // Feedback
            .route("/feedback", web::get().to(handlers::list_feedback))
            .route("/feedback/export", web::get().to(handlers::export_feedback))
            .route(
                "/feedback/archive",
                web::get().to(handlers::list_feedback_archive),
            )
            .route(
                "/feedback/archive/{archive_id}/restore",
                web::post().to(handlers::restore_feedback),
            )
            .route(
                "/feedback/{feedback_id}/attachments/{attachment_id}",
                web::get().to(handlers::get_attachment),
            )
            .route(
                "/feedback/{feedback_id}",
                web::get().to(handlers::get_feedback),
            )
            .route(
                "/feedback/{feedback_id}/respond",
                web::post().to(handlers::respond_to_feedback),
            )
            .route(
                "/feedback/{feedback_id}/status",
                web::put().to(handlers::update_feedback_status),
            )
            .route(
                "/feedback/{feedback_id}/mark-spam",
                web::post().to(handlers::mark_feedback_spam),
            )
            .route(
                "/feedback/{feedback_id}/unmark-spam",
                web::post().to(handlers::unmark_feedback_spam),
            )
            .route(
                "/feedback/{feedback_id}/archive",
                web::post().to(handlers::archive_feedback),
            )
            .route(
                "/feedback/{feedback_id}",
                web::delete().to(handlers::delete_feedback),
            )
            // Test email
            .route("/test-email", web::post().to(handlers::send_test_email))
            // OIDC per-RP user-tenant assignments (BUNYIP-61).
            .route(
                "/oauth-clients/{client_id}/user-tenants",
                web::get().to(handlers::list_client_assignments),
            )
            .route(
                "/oauth-clients/{client_id}/user-tenants",
                web::post().to(handlers::assign_user_tenant),
            )
            .route(
                "/oauth-clients/{client_id}/user-tenants/{assignment_id}",
                web::delete().to(handlers::unassign_user_tenant),
            )
            // Admin Invites
            .route("/invites", web::post().to(handlers::create_admin_invite))
            .route("/invites", web::get().to(handlers::list_admin_invites))
            .route(
                "/invites/{invite_id}",
                web::delete().to(handlers::revoke_admin_invite),
            )
            // Tier config
            .route("/tier-config", web::get().to(handlers::get_tier_config))
            .route("/tier-config", web::put().to(handlers::update_tier_config))
            // Email config (BUNYIP-351)
            .route("/email", web::get().to(handlers::get_email_config))
            .route("/email", web::put().to(handlers::update_email_config))
            // Auto-ban config (BUNYIP-351)
            .route(
                "/auto-ban-config",
                web::get().to(handlers::get_auto_ban_config),
            )
            .route(
                "/auto-ban-config",
                web::put().to(handlers::update_auto_ban_config),
            )
            // Stripe config
            .route("/stripe", web::get().to(handlers::get_stripe_config))
            .route("/stripe", web::put().to(handlers::update_stripe_config))
            // Stripe products
            .route(
                "/stripe/products",
                web::get().to(handlers::list_stripe_products),
            )
            .route(
                "/stripe/products",
                web::post().to(handlers::create_stripe_product),
            )
            .route(
                "/stripe/products/{id}",
                web::put().to(handlers::update_stripe_product),
            )
            .route(
                "/stripe/products/{id}",
                web::delete().to(handlers::archive_stripe_product),
            )
            // Stripe prices
            .route(
                "/stripe/prices",
                web::get().to(handlers::list_stripe_prices),
            )
            .route(
                "/stripe/prices",
                web::post().to(handlers::create_stripe_price),
            )
            .route(
                "/stripe/prices/{id}",
                web::delete().to(handlers::archive_stripe_price),
            )
            // Stripe webhooks
            .route(
                "/stripe/webhooks",
                web::get().to(handlers::list_stripe_webhooks),
            )
            .route(
                "/stripe/webhooks",
                web::post().to(handlers::create_stripe_webhook),
            )
            .route(
                "/stripe/webhooks/{id}",
                web::delete().to(handlers::delete_stripe_webhook),
            )
            // Notifications
            .route(
                "/notifications",
                web::get().to(handlers::list_notifications),
            )
            .route(
                "/notifications/{notification_id}/read",
                web::post().to(handlers::mark_notification_read),
            )
            .route(
                "/notifications/read-all",
                web::post().to(handlers::mark_all_notifications_read),
            )
            // Key rotation
            .route(
                "/key-rotation/{key_id}/status",
                web::get().to(handlers::key_rotation_status),
            )
            .route(
                "/key-rotation/{key_id}/reencrypt",
                web::post().to(handlers::reencrypt_key),
            ),
    );
}
