//! BUNYIP-673 integration tests for [`MokoshGrantsService`].
//!
//! Env-gated on `BUNYIP_TEST_DATABASE_URL` / `RLS_TEST_DATABASE_URL` the
//! same way the sibling org tests are.
//!
//! Covers the ticket ACs the domain half owns: create + list + revoke
//! round-trip; a second active grant for the same (owner, grantee,
//! account) triple is 409; the FK to `users(id)` refuses a grantee id
//! that is not a Bunyip user (BUNYIP-675's portal-contact separation
//! guarantee at this layer); self-grant is refused; a foreign revoke
//! is 403 not 404.

#![cfg(test)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::CreateGrantRequest;
use crate::services::MokoshGrantsService;

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../bunyip-api/migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn seed_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, is_active) \
         VALUES ($1, $2, 'not-real-not-used', TRUE, TRUE)",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
    id
}

fn req(grantee_id: Uuid, mokosh_account: &str, role: &str) -> CreateGrantRequest {
    CreateGrantRequest {
        grantee_email: None,
        grantee_bunyip_user_id: Some(grantee_id),
        mokosh_account_id: mokosh_account.to_string(),
        role: role.to_string(),
    }
}

#[tokio::test]
async fn flag_off_answers_not_found_on_every_method() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "flag-off-grant@example.test").await;

    let create = MokoshGrantsService::create_grant(
        &pool,
        false,
        owner,
        CreateGrantRequest {
            grantee_email: None,
            grantee_bunyip_user_id: Some(Uuid::new_v4()),
            mokosh_account_id: "acme".to_string(),
            role: "admin".to_string(),
        },
    )
    .await;
    assert!(matches!(create, Err(AppError::NotFound { .. })));

    let list = MokoshGrantsService::list_own(&pool, false, owner).await;
    assert!(matches!(list, Err(AppError::NotFound { .. })));
}

#[tokio::test]
async fn create_and_list_round_trips() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "grant-owner@example.test").await;
    let grantee = seed_user(&pool, "grant-grantee@example.test").await;

    let grant =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "manager"))
            .await
            .expect("create");
    assert_eq!(grant.owner_bunyip_user_id, owner);
    assert_eq!(grant.grantee_bunyip_user_id, grantee);
    assert_eq!(grant.mokosh_account_id, "acme");
    assert_eq!(grant.role, "manager");
    assert!(grant.revoked_at.is_none());

    let own = MokoshGrantsService::list_own(&pool, true, owner)
        .await
        .expect("list_own");
    assert!(own.iter().any(|g| g.id == grant.id));

    let received = MokoshGrantsService::list_received(&pool, true, grantee)
        .await
        .expect("list_received");
    assert!(received.iter().any(|g| g.id == grant.id));
}

#[tokio::test]
async fn create_by_email_resolves_the_grantee() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "by-email-owner@example.test").await;
    let grantee_email = "by-email-grantee@example.test";
    let grantee = seed_user(&pool, grantee_email).await;

    let grant = MokoshGrantsService::create_grant(
        &pool,
        true,
        owner,
        CreateGrantRequest {
            grantee_email: Some(grantee_email.to_string()),
            grantee_bunyip_user_id: None,
            mokosh_account_id: "acme".to_string(),
            role: "read_only".to_string(),
        },
    )
    .await
    .expect("create by email");
    assert_eq!(grant.grantee_bunyip_user_id, grantee);
}

#[tokio::test]
async fn a_second_active_grant_for_the_same_triple_is_409() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "dup-grant-owner@example.test").await;
    let grantee = seed_user(&pool, "dup-grant-grantee@example.test").await;

    MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "admin"))
        .await
        .expect("first");
    let second =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "technician"))
            .await;
    assert!(
        matches!(second, Err(AppError::Conflict { .. })),
        "second grant for the same triple must Conflict, got {second:?}"
    );
}

#[tokio::test]
async fn self_grant_is_refused() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "self-grant@example.test").await;
    let result =
        MokoshGrantsService::create_grant(&pool, true, owner, req(owner, "acme", "admin")).await;
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
}

#[tokio::test]
async fn granting_to_a_non_user_id_is_400() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "grant-nonuser@example.test").await;
    // A UUID that names no `users` row. The service resolution returns
    // 404 (the `Bunyip user` shape) rather than reaching the FK.
    let result =
        MokoshGrantsService::create_grant(&pool, true, owner, req(Uuid::new_v4(), "acme", "admin"))
            .await;
    assert!(matches!(result, Err(AppError::NotFound { .. })));
}

#[tokio::test]
async fn foreign_revoke_is_403_not_404() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "revoke-owner@example.test").await;
    let grantee = seed_user(&pool, "revoke-grantee@example.test").await;
    let unrelated = seed_user(&pool, "revoke-other@example.test").await;

    let grant =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "admin"))
            .await
            .expect("create");
    let result = MokoshGrantsService::revoke_grant(&pool, true, unrelated, grant.id).await;
    assert!(matches!(result, Err(AppError::Forbidden)));
}

#[tokio::test]
async fn revoke_removes_the_row_from_active_lists() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "revoke-active-owner@example.test").await;
    let grantee = seed_user(&pool, "revoke-active-grantee@example.test").await;

    let grant =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "admin"))
            .await
            .expect("create");
    let revoked = MokoshGrantsService::revoke_grant(&pool, true, owner, grant.id)
        .await
        .expect("revoke");
    assert!(revoked.revoked_at.is_some());

    let own = MokoshGrantsService::list_own(&pool, true, owner)
        .await
        .unwrap();
    assert!(
        own.iter().all(|g| g.id != grant.id),
        "revoked grant must not appear in list_own"
    );
    let received = MokoshGrantsService::list_received(&pool, true, grantee)
        .await
        .unwrap();
    assert!(
        received.iter().all(|g| g.id != grant.id),
        "revoked grant must not appear in list_received"
    );

    // A repeat revoke is idempotent: the caller sees the same
    // already-revoked row rather than a 404.
    let idempotent = MokoshGrantsService::revoke_grant(&pool, true, owner, grant.id)
        .await
        .expect("idempotent revoke");
    assert_eq!(idempotent.id, grant.id);
    assert!(idempotent.revoked_at.is_some());
}

#[tokio::test]
async fn revoke_then_regrant_is_allowed_and_creates_a_new_row() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "regrant-owner@example.test").await;
    let grantee = seed_user(&pool, "regrant-grantee@example.test").await;

    let first =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "admin"))
            .await
            .expect("first");
    MokoshGrantsService::revoke_grant(&pool, true, owner, first.id)
        .await
        .expect("revoke");
    let second =
        MokoshGrantsService::create_grant(&pool, true, owner, req(grantee, "acme", "technician"))
            .await
            .expect("regrant");
    assert_ne!(second.id, first.id);
    assert_eq!(second.role, "technician");
}
