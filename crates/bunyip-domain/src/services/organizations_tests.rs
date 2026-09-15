//! BUNYIP-672 integration tests for [`OrganizationsService`] / [`TeamsService`].
//!
//! Env-gated the same way `mailer_relay.rs` does: with `BUNYIP_TEST_DATABASE_URL`
//! or `RLS_TEST_DATABASE_URL` unset the tests skip and stay green, so CI
//! without a Postgres service does not go red. Set one to a throwaway
//! database and the tests migrate + exercise the service directly against
//! the pool.
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_672_test \
//!   cargo test -p bunyip-domain --lib services::organizations_tests
//! ```
//!
//! Testing at the service layer (rather than through the actix stack)
//! covers every ticket AC without also standing up JWT verification,
//! rate-limit floor and tier config plumbing, all of which are exercised
//! by other integration files. Flag-off = 404, duplicate owner = 409,
//! CRUD round-trip.

#![cfg(test)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::services::{OrganizationsService, TeamsService};

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

#[tokio::test]
async fn flag_off_answers_not_found_on_every_service_method() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let user = seed_user(&pool, "flag-off@example.test").await;

    let create = OrganizationsService::create(&pool, false, user, "Ops").await;
    assert!(matches!(create, Err(AppError::NotFound { .. })));

    let get_own = OrganizationsService::get_own(&pool, false, user).await;
    assert!(matches!(get_own, Err(AppError::NotFound { .. })));

    let list_teams = TeamsService::list(&pool, false, user).await;
    assert!(matches!(list_teams, Err(AppError::NotFound { .. })));
}

#[tokio::test]
async fn flag_on_organization_crud_round_trips() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let user = seed_user(&pool, "crud@example.test").await;

    let org = OrganizationsService::create(&pool, true, user, "Ops")
        .await
        .expect("create");
    assert_eq!(org.name, "Ops");
    assert_eq!(org.owner_bunyip_user_id, user);

    let fetched = OrganizationsService::get_own(&pool, true, user)
        .await
        .expect("get_own")
        .expect("some");
    assert_eq!(fetched.id, org.id);

    let renamed = OrganizationsService::update_own(&pool, true, user, "Ops Team")
        .await
        .expect("update");
    assert_eq!(renamed.name, "Ops Team");
    assert_eq!(renamed.id, org.id);
}

#[tokio::test]
async fn a_second_create_by_the_same_owner_is_409() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let user = seed_user(&pool, "dup@example.test").await;

    OrganizationsService::create(&pool, true, user, "First")
        .await
        .expect("first create");

    let second = OrganizationsService::create(&pool, true, user, "Second").await;
    assert!(
        matches!(second, Err(AppError::Conflict { .. })),
        "second create must be a Conflict, got {second:?}"
    );
}

#[tokio::test]
async fn team_crud_round_trips_including_members() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "team-owner@example.test").await;
    let member = seed_user(&pool, "team-member@example.test").await;

    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");

    let team = TeamsService::create(&pool, true, owner, "SRE", Some("On-call"))
        .await
        .expect("create team");
    assert_eq!(team.name, "SRE");

    let teams = TeamsService::list(&pool, true, owner).await.expect("list");
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].id, team.id);

    let renamed = TeamsService::update(&pool, true, owner, team.id, "Platform", None)
        .await
        .expect("update team");
    assert_eq!(renamed.name, "Platform");
    assert_eq!(renamed.description, None);

    let added = TeamsService::add_member(&pool, true, owner, team.id, member, "member")
        .await
        .expect("add member");
    assert_eq!(added.bunyip_user_id, member);
    assert_eq!(added.role, "member");

    let members = TeamsService::list_members(&pool, true, owner, team.id)
        .await
        .expect("list members");
    assert_eq!(members.len(), 1);

    let promoted = TeamsService::update_member_role(&pool, true, owner, team.id, member, "leader")
        .await
        .expect("update member role");
    assert_eq!(promoted.role, "leader");

    TeamsService::remove_member(&pool, true, owner, team.id, member)
        .await
        .expect("remove member");

    TeamsService::delete(&pool, true, owner, team.id)
        .await
        .expect("delete team");

    let final_list = TeamsService::list(&pool, true, owner).await.expect("list");
    assert!(final_list.is_empty());
}
