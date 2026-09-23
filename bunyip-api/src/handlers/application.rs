//! Application handlers
//!
//! This module contains HTTP handlers for application endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::{request_user, OptionalUser};
use crate::models::ApplicationResponse;
use crate::repositories::{
    ApplicationGroupRepository, ApplicationRepository, EntitlementRepository, UserRepository,
};
use crate::responses::{get_request_id, success};
use crate::services::AccessTokenClaims;

/// BUNYIP-229: resolve `has_member_access` from the DB user row instead of
/// the JWT claim cache. The JWT was minted at login (or last refresh) and
/// holds a snapshot of `trial_ends_at`, `lifetime_member`, `membership_status`
/// that goes stale the moment ANY out-of-band path flips one of them: a
/// cross-browser email verify firing BUNYIP-221's grant, an admin tier flip
/// from /admin/users, a scheduled trial expiry, the BUNYIP-225 sibling-sub
/// cancel cleanup. The launcher reads this access bit on every dashboard
/// load, so a one-row DB read here is the simplest correctness fix that
/// works regardless of which handler caused the flip.
///
/// Anonymous callers (no claims) get `false` per existing semantics. A DB
/// read failure for an authenticated user falls back to the JWT cache so the
/// endpoint never errors out for a transient outage.
///
/// BUNYIP-557: an at+jwt caller's row was already read from the database while
/// verifying the token, earlier in THIS request, so that copy answers here
/// instead of an identical third `SELECT`. This does not weaken the freshness
/// BUNYIP-229 is about: the row is still read per request, microseconds
/// before this call, never carried over from an earlier one.
async fn resolve_has_member_access(req: &HttpRequest, pool: &PgPool, user: &OptionalUser) -> bool {
    let Some(claims) = user.0.as_ref() else {
        return false;
    };
    if let Some(u) = request_user(req) {
        return AccessTokenClaims::has_member_access_static(
            &u.role,
            u.lifetime_member,
            u.trial_ends_at.map(|t| t.timestamp()),
            &u.membership_status,
            u.grace_period_end.map(|t| t.timestamp()),
        );
    }
    match UserRepository::find_by_id(pool, claims.sub).await {
        Ok(Some(u)) => AccessTokenClaims::has_member_access_static(
            &u.role,
            u.lifetime_member,
            u.trial_ends_at.map(|t| t.timestamp()),
            &u.membership_status,
            u.grace_period_end.map(|t| t.timestamp()),
        ),
        Ok(None) => claims.has_member_access(),
        Err(e) => {
            // Best effort by design (above), but never silent: the answer here
            // is the stale claim, and that has to be diagnosable.
            tracing::warn!(
                error = %e,
                user_id = %claims.sub,
                "member access fell back to the token claim: user row read failed"
            );
            claims.has_member_access()
        }
    }
}

/// GET /v1/application-groups
/// List application groups (display metadata) so the web layer can render
/// applications grouped under their group heading. Public: groups carry no
/// sensitive data, and membership/entitlement gating stays on the apps.
pub async fn list_application_groups(
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let groups = ApplicationGroupRepository::list(&pool).await?;
    Ok(success(serde_json::json!({ "groups": groups }), request_id))
}

/// The per-caller visibility gate for the catalog list. An open product is
/// always visible, an admin always sees everything, and a signed-in caller
/// sees a restricted product only when their entitlement id set carries it.
/// Extracted as a pure function so it can be unit-tested without seeding a
/// database.
fn catalog_visible(
    app: &crate::models::Application,
    is_admin: bool,
    entitled_ids: &[uuid::Uuid],
) -> bool {
    !app.requires_entitlement || is_admin || entitled_ids.contains(&app.id)
}

/// GET /v1/applications
/// List active HOSTED applications (hub launch tiles). Catalog-only
/// distribution products are excluded; they surface via /v1/downloads and
/// the OCI registry instead.
///
/// A restricted product (BUNYIP-39) is dropped from the response for a
/// caller who is not entitled, so the list does not leak the existence of
/// products a standard user cannot reach and cannot see the metadata of.
/// `get_application` (singular) already refuses them; the list route did
/// not, so an anonymous or non-entitled caller received their names,
/// icons and subdomains alongside `is_accessible: false`. Admins and the
/// entitled see the same set they did before.
pub async fn list_applications(
    req: HttpRequest,
    user: OptionalUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // BUNYIP-229: read fresh from DB instead of trusting the JWT claim
    // cache. See `resolve_has_member_access` for why.
    let has_access = resolve_has_member_access(&req, &pool, &user).await;

    let apps = ApplicationRepository::list_active_hosted(&pool).await?;

    // A caller's identity for the per-product gate. Anonymous callers use
    // the nil uuid: `is_allowed` short-circuits open products anyway, and
    // `active_application_ids` for a signed-out visitor returns an empty
    // set with one query rather than one per restricted row.
    let (user_id, is_admin) = user
        .0
        .as_ref()
        .map(|claims| (claims.sub, claims.role == "admin"))
        .unwrap_or((uuid::Uuid::nil(), false));

    // Batch the entitlement lookup so a tenant with a hundred restricted
    // products does not pay a hundred round trips per list render.
    let entitled_ids = if is_admin || user.0.is_none() {
        Vec::new()
    } else {
        EntitlementRepository::active_application_ids(pool.as_ref(), user_id).await?
    };

    let apps_response: Vec<ApplicationResponse> = apps
        .into_iter()
        .filter(|app| catalog_visible(app, is_admin, &entitled_ids))
        .map(|app| ApplicationResponse::from_application(app, has_access))
        .collect();

    Ok(success(
        serde_json::json!({ "applications": apps_response }),
        request_id,
    ))
}

/// GET /v1/applications/{slug}
/// Get a specific application by slug
pub async fn get_application(
    req: HttpRequest,
    user: OptionalUser,
    path: web::Path<String>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slug = path.into_inner();

    // BUNYIP-229: read fresh from DB instead of trusting the JWT claim cache.
    let has_access = resolve_has_member_access(&req, &pool, &user).await;

    let app = ApplicationRepository::find_active_by_slug(&pool, &slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    // A restricted product (BUNYIP-39) must not leak its existence/metadata to
    // a caller who is not entitled. Treat it as not found for anyone who is not
    // an admin or actively entitled (anonymous callers included). Open products
    // are unaffected (is_allowed short-circuits).
    let (user_id, is_admin) = user
        .0
        .as_ref()
        .map(|claims| (claims.sub, claims.role == "admin"))
        .unwrap_or((uuid::Uuid::nil(), false));
    if !EntitlementRepository::is_allowed(&pool, user_id, is_admin, &app).await? {
        return Err(AppError::not_found("Application"));
    }

    let app_response = ApplicationResponse::from_application(app, has_access);

    Ok(success(app_response, request_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::{verify_once, AtJwtVerifier};
    use crate::models::User;
    use actix_web::http::header;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sqlx::postgres::PgPoolOptions;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Stands in for `OidcProvider`. Each call is one EdDSA verification plus
    /// one `SELECT ... FROM users` in the real implementation
    /// (`resolve_user_for_atjwt`), so the counter is the statement count
    /// BUNYIP-557 is about.
    struct CountingVerifier {
        claims: AccessTokenClaims,
        user: User,
        calls: Mutex<u32>,
    }

    #[async_trait::async_trait]
    impl AtJwtVerifier for CountingVerifier {
        async fn verify_and_resolve(
            &self,
            _token: &str,
        ) -> Result<(AccessTokenClaims, User), AppError> {
            *self.calls.lock().unwrap() += 1;
            Ok((self.claims.clone(), self.user.clone()))
        }
    }

    /// An at+jwt shell: only the header `typ` is decoded when routing.
    fn atjwt() -> String {
        let header = r#"{"alg":"EdDSA","typ":"at+jwt","kid":"k1"}"#;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#),
            URL_SAFE_NO_PAD.encode("filler"),
        )
    }

    fn stale_claims(user: &User) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
            // The staleness BUNYIP-229 exists for: the token was minted before
            // the membership was granted.
            membership_status: "canceled".to_string(),
            price_locked: false,
            price_id: None,
            lifetime_member: false,
            trial_ends_at: None,
            grace_period_end: None,
            iat: 0,
            exp: i64::MAX,
            jti: "jti-557".to_string(),
            iss: "https://api.example.test".to_string(),
        }
    }

    fn member_row() -> User {
        User {
            id: uuid::Uuid::from_u128(557),
            email: "member@example.test".to_string(),
            email_verified: true,
            password_hash: None,
            role: "subscriber".to_string(),
            stripe_customer_id: None,
            stripe_payment_method_id: None,
            membership_status: "active".to_string(),
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            grace_period_start: None,
            grace_period_end: None,
            two_factor_enabled: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login_at: None,
            last_login_country: None,
            login_location_alerts: true,
            deleted_at: None,
            membership_tier: "standard".to_string(),
            trial_ends_at: None,
            lifetime_member: false,
            membership_override_by: None,
            first_name: None,
            last_name: None,
            phone: None,
            has_used_trial: false,
            avatar_updated_at: None,
            is_super_admin: false,
        }
    }

    /// A pool that can never answer a query, so any read this handler still
    /// issues fails fast instead of being mistaken for a cache hit.
    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy("postgres://user:pw@127.0.0.1:1/none")
            .expect("lazy pool builds without connecting")
    }

    /// BUNYIP-557: the third `SELECT ... FROM users` is gone. The row the
    /// at+jwt verification read earlier in this request answers the access
    /// question, and it is the DB row (active), not the stale claim
    /// (canceled), so BUNYIP-229's freshness is intact.
    #[actix_rt::test]
    async fn member_access_reads_the_row_the_verification_already_read() {
        let user = member_row();
        let claims = stale_claims(&user);
        let counting = Arc::new(CountingVerifier {
            claims: claims.clone(),
            user,
            calls: Mutex::new(0),
        });
        let verifier: Arc<dyn AtJwtVerifier> = counting.clone();
        let token = atjwt();
        let req = actix_web::test::TestRequest::default()
            .app_data(verifier)
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
            .to_http_request();

        // The floor, then the extractor: one verification between them.
        assert!(crate::middleware::resolve_rate_limit_subject(&req)
            .await
            .is_some());
        let extracted = OptionalUser(Some(verify_once(&req, &token).await.unwrap().claims));

        let pool = unreachable_pool();
        assert!(
            resolve_has_member_access(&req, &pool, &extracted).await,
            "the handler must answer from the row this request already read, \
             not from the stale claim and not from a third query"
        );
        assert_eq!(
            *counting.calls.lock().unwrap(),
            1,
            "one at+jwt request reads the users row exactly once"
        );
        pool.close().await;
    }

    /// The HS256 cookie path caches no row (it reads none while verifying), so
    /// this handler still queries, exactly as before BUNYIP-557.
    #[actix_rt::test]
    async fn member_access_still_queries_when_no_row_was_cached() {
        let user = member_row();
        let claims = stale_claims(&user);
        let req = actix_web::test::TestRequest::default().to_http_request();
        let pool = unreachable_pool();

        // The query fails against the dead pool, so the answer falls back to
        // the claim. That it is the CLAIM's value proves a query was attempted.
        assert!(
            !resolve_has_member_access(&req, &pool, &OptionalUser(Some(claims))).await,
            "with nothing cached the handler must fall back to its own query"
        );
        pool.close().await;
    }

    #[actix_rt::test]
    async fn anonymous_callers_have_no_member_access() {
        let req = actix_web::test::TestRequest::default().to_http_request();
        let pool = unreachable_pool();
        assert!(!resolve_has_member_access(&req, &pool, &OptionalUser(None)).await);
        pool.close().await;
    }

    /// The catalog-visibility gate: pure filter logic, tested without a pool.
    /// Every arm the handler branches on lives here so a change to the rule
    /// is a change to this test.
    mod catalog_visible {
        use super::super::catalog_visible;
        use crate::models::Application;
        use chrono::Utc;
        use uuid::Uuid;

        fn app(id: Uuid, requires_entitlement: bool) -> Application {
            Application {
                id,
                name: "test".to_string(),
                slug: "test".to_string(),
                display_name: "Test".to_string(),
                description: None,
                icon_url: None,
                is_active: true,
                is_hosted: true,
                requires_entitlement,
                maintenance_mode: false,
                maintenance_message: None,
                subdomain: None,
                container_name: "test".to_string(),
                health_check_url: None,
                webhook_url: None,
                version: None,
                source_code_url: None,
                release_notes_url: None,
                forgejo_owner: None,
                forgejo_repo: None,
                pinned_release_tag: None,
                artifact_source: "release".to_string(),
                forgejo_package: None,
                oci_image_owner: None,
                oci_image_name: None,
                pinned_image_tag: None,
                sort_order: 0,
                group_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        #[test]
        fn an_open_product_is_always_visible() {
            let open = app(Uuid::from_u128(1), false);
            for (is_admin, entitled) in [
                (false, &[][..]),
                (true, &[][..]),
                (false, &[Uuid::from_u128(2)][..]),
            ] {
                assert!(
                    catalog_visible(&open, is_admin, entitled),
                    "open product must be visible whatever the caller shape"
                );
            }
        }

        #[test]
        fn a_restricted_product_hides_from_a_standard_caller() {
            let restricted = app(Uuid::from_u128(3), true);
            assert!(
                !catalog_visible(&restricted, false, &[]),
                "an anonymous or non-entitled caller must not see restricted product metadata"
            );
            assert!(
                !catalog_visible(&restricted, false, &[Uuid::from_u128(999)]),
                "a caller entitled to a different product must not see this restricted one"
            );
        }

        #[test]
        fn a_restricted_product_shows_for_an_admin_or_an_entitled_caller() {
            let id = Uuid::from_u128(5);
            let restricted = app(id, true);
            assert!(
                catalog_visible(&restricted, true, &[]),
                "an admin sees restricted products even without an entitlement"
            );
            assert!(
                catalog_visible(&restricted, false, &[id]),
                "an entitled caller sees the restricted product"
            );
        }
    }
}
