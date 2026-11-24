//! BUNYIP-672: organizations + teams + team members, flag-gated on `orgs_enabled`.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or the
//! `RLS_TEST_DATABASE_URL` fallback). Skips when neither is set.

use bunyip_api::errors::AppError;
use bunyip_api::models::{CreateUser, User, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{OrganizationService, TeamService};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!("BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn seed_user(pool: &PgPool) -> User {
    UserRepository::create(
        pool,
        CreateUser {
            email: format!("orgs-{}@example.test", Uuid::new_v4().simple()),
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user")
}

fn is_not_found(err: &AppError) -> bool {
    matches!(err, AppError::NotFound { .. })
}

fn is_conflict(err: &AppError) -> bool {
    matches!(err, AppError::Conflict { .. })
}

/// Flag off, every service method returns `NotFound("Organizations feature is
/// disabled")` so the HTTP surface serves a 404 (BUNYIP-493 pattern).
#[actix_rt::test]
async fn flag_off_hides_every_service_method() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = seed_user(&pool).await;

    let create = OrganizationService::create_organization(&pool, false, user.id, "Acme".into())
        .await
        .unwrap_err();
    assert!(is_not_found(&create), "flag off is not-found: {create:?}");

    let get = OrganizationService::get_organization_by_owner(&pool, false, user.id)
        .await
        .unwrap_err();
    assert!(is_not_found(&get), "flag off is not-found: {get:?}");

    let list = TeamService::list_teams(&pool, false, Uuid::new_v4(), user.id)
        .await
        .unwrap_err();
    assert!(is_not_found(&list), "flag off is not-found: {list:?}");
}

/// Flag on, create/get/update an organization; a second create for the same
/// owner returns Conflict so the UNIQUE(owner_bunyip_user_id) constraint is
/// visible at the service layer.
#[actix_rt::test]
async fn flag_on_round_trip_and_duplicate_conflict() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = seed_user(&pool).await;

    assert!(
        OrganizationService::get_organization_by_owner(&pool, true, user.id)
            .await
            .expect("get before create")
            .is_none(),
        "no org before create"
    );

    let org = OrganizationService::create_organization(&pool, true, user.id, "Acme".into())
        .await
        .expect("create org");
    assert_eq!(org.name, "Acme");
    assert_eq!(org.owner_bunyip_user_id, user.id);

    let got = OrganizationService::get_organization_by_owner(&pool, true, user.id)
        .await
        .expect("get after create")
        .expect("org exists");
    assert_eq!(got.id, org.id);

    let dup = OrganizationService::create_organization(&pool, true, user.id, "Acme 2".into())
        .await
        .unwrap_err();
    assert!(is_conflict(&dup), "duplicate owner is a conflict: {dup:?}");

    let renamed = OrganizationService::update_organization(&pool, true, user.id, "Acme Inc".into())
        .await
        .expect("rename");
    assert_eq!(renamed.name, "Acme Inc");
}

/// Teams and members: CRUD under the owner, cross-owner access is 404, same
/// name twice is Conflict, same user twice is Conflict.
#[actix_rt::test]
async fn teams_and_members_crud_and_isolation() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let owner = seed_user(&pool).await;
    let member = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;

    let org = OrganizationService::create_organization(&pool, true, owner.id, "Acme".into())
        .await
        .expect("create org");

    // Only the owner sees their teams: a stranger probing the id gets 404.
    let probe = TeamService::list_teams(&pool, true, org.id, stranger.id)
        .await
        .unwrap_err();
    assert!(is_not_found(&probe), "cross-owner probe is 404: {probe:?}");

    let team = TeamService::create_team(
        &pool,
        true,
        org.id,
        owner.id,
        "Platform".into(),
        Some("Infra".into()),
    )
    .await
    .expect("create team");

    let dup = TeamService::create_team(&pool, true, org.id, owner.id, "Platform".into(), None)
        .await
        .unwrap_err();
    assert!(
        is_conflict(&dup),
        "duplicate team name is conflict: {dup:?}"
    );

    let listed = TeamService::list_teams(&pool, true, org.id, owner.id)
        .await
        .expect("list teams");
    assert_eq!(listed.len(), 1);

    TeamService::add_member(&pool, true, team.id, owner.id, member.id, None)
        .await
        .expect("add member");

    let dup_member = TeamService::add_member(&pool, true, team.id, owner.id, member.id, None)
        .await
        .unwrap_err();
    assert!(is_conflict(&dup_member), "dup member is conflict");

    let members = TeamService::list_members(&pool, true, team.id, owner.id)
        .await
        .expect("list members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].bunyip_user_id, member.id);
    assert_eq!(members[0].role, "member");

    let updated =
        TeamService::update_member_role(&pool, true, team.id, owner.id, member.id, "lead".into())
            .await
            .expect("update role");
    assert_eq!(updated.role, "lead");

    TeamService::remove_member(&pool, true, team.id, owner.id, member.id)
        .await
        .expect("remove member");

    let empty = TeamService::list_members(&pool, true, team.id, owner.id)
        .await
        .expect("list members after remove");
    assert!(empty.is_empty());

    TeamService::delete_team(&pool, true, team.id, owner.id)
        .await
        .expect("delete team");
    let after = TeamService::list_teams(&pool, true, org.id, owner.id)
        .await
        .expect("list after delete");
    assert!(after.is_empty());
}
