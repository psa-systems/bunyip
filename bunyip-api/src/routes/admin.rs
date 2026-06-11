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
            .route(
                "/applications/{slug}/downloads/refresh",
                web::post().to(handlers::admin_refresh_release),
            )
            .route(
                "/applications/{slug}/oci/refresh",
                web::post().to(bunyip_oci::handlers::admin_oci::refresh_oci),
            )
            // Audit logs
            .route("/audit-logs", web::get().to(handlers::list_audit_logs))
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
