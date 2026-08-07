//! User model and related types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// The account vocabulary (roles, membership status, membership tier) lives in
// the shared `dunite-user-core` crate (DEV-517) and is re-exported here, so
// `crate::models::user::*` paths are unchanged and a8n-tools and bunyip cannot
// drift on the string values or on the tier-selection boundary. The `User` row
// struct below stays bunyip-side: it carries columns a8n's schema does not have.
pub use dunite_user_core::{MembershipStatus, UserRole};

// BUNYIP-488: dunite still names the enum `SubscriptionTier`; DUNITE-7 renames it.
// Bridge here so bunyip reads `MembershipTier` now, and delete this alias when the
// dunite `rev` is bumped.
pub use dunite_user_core::SubscriptionTier as MembershipTier;

/// User database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub role: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_payment_method_id: Option<String>,
    pub membership_status: String,
    pub price_locked: bool,
    pub locked_price_id: Option<String>,
    pub locked_price_amount: Option<i32>,
    pub grace_period_start: Option<DateTime<Utc>>,
    pub grace_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub two_factor_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    /// BUNYIP-366: ISO 3166-1 alpha-2 country of the user's last geolocatable
    /// login, or `None` until the first one. Compared against the current login's
    /// country to detect a significant location change.
    pub last_login_country: Option<String>,
    /// BUNYIP-366: per-user opt-out for the new-login-location email alert
    /// (default TRUE).
    pub login_location_alerts: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Tier assigned at email verification: 'lifetime', 'early_adopter', 'standard'
    pub membership_tier: String,
    /// Null for lifetime members; set for trial members
    pub trial_ends_at: Option<DateTime<Utc>>,
    /// True for the first `lifetime_slots` verified users (the `TIER_LIFETIME_SLOTS`
    /// config, default 5) and admin-granted lifetime members
    pub lifetime_member: bool,
    /// Set when an admin manually granted lifetime membership
    pub membership_override_by: Option<Uuid>,
    /// BUNYIP-139: optional given name. Nullable in the DB (legacy rows have no
    /// source). Flowed as the OIDC `given_name` claim under the `profile` scope
    /// by BUNYIP-140.
    pub first_name: Option<String>,
    /// BUNYIP-139: optional family name. Flowed as `family_name` under the
    /// `profile` scope by BUNYIP-140.
    pub last_name: Option<String>,
    /// BUNYIP-139: optional phone number. Flowed as `phone_number` under the
    /// `phone` scope by BUNYIP-140. No format normalization at the DB layer;
    /// the Settings form trims whitespace but otherwise stores verbatim.
    pub phone: Option<String>,
    /// BUNYIP-209: TRUE once the user has been issued a Stripe Checkout session
    /// that carried the signup free trial (flipped by the
    /// `checkout.session.completed` webhook). Trial-eligibility is `!has_used_trial`,
    /// so a returning user never re-triggers the trial.
    pub has_used_trial: bool,
    /// BUNYIP-408: timestamp of the user's most recent avatar upload, or `None`
    /// when no avatar is set. The bytes live in the separate `user_avatars`
    /// table; this column is the cheap "an avatar exists" marker (so the hot
    /// user-fetch path never loads the BYTEA) and doubles as a cache-busting
    /// version for the avatar `<img>` URL. Set/cleared in the same transaction
    /// that writes/deletes the `user_avatars` row.
    pub avatar_updated_at: Option<DateTime<Utc>>,
    /// BUNYIP-413: the "first setup account" flag. Set on the bootstrap admin
    /// when it is promoted (and backfilled onto the earliest-created admin by
    /// the migration). Gates the rate-limit and IP-ban management surfaces,
    /// which can lock the platform out for everybody.
    pub is_super_admin: bool,
}

impl User {
    /// Get the user's role as enum
    pub fn role_enum(&self) -> UserRole {
        UserRole::from(self.role.as_str())
    }

    /// Get the user's membership status as enum
    pub fn membership_status_enum(&self) -> MembershipStatus {
        MembershipStatus::from(self.membership_status.as_str())
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }

    /// Check if user has active membership
    pub fn has_active_membership(&self) -> bool {
        self.membership_status_enum().has_access()
    }

    /// Check if user is soft deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Get the user's membership tier as enum
    pub fn membership_tier_enum(&self) -> MembershipTier {
        MembershipTier::from(self.membership_tier.as_str())
    }

    /// Whether a new checkout should carry the one-time signup free trial
    /// (BUNYIP-209 / BUNYIP-225). Eligible only until the trial has been used:
    /// a returning member who cancels and resubscribes has `has_used_trial =
    /// true`, so they bill immediately with no second free trial.
    pub fn trial_eligible(&self) -> bool {
        !self.has_used_trial
    }

    /// Check if the user is allowed to access protected features.
    ///
    /// Access is granted when ANY of the following are true:
    /// - User is an admin (admins bypass all access checks)
    /// - User is a lifetime member
    /// - User's trial has not yet expired
    /// - User has an active/grace-period membership
    pub fn is_access_allowed(&self) -> bool {
        if self.is_admin() {
            return true;
        }
        if self.lifetime_member {
            return true;
        }
        if let Some(trial_ends_at) = self.trial_ends_at {
            if trial_ends_at > chrono::Utc::now() {
                return true;
            }
        }
        self.membership_status_enum().has_access()
    }
}

/// Normalize an email address for storage (BUNYIP-325).
///
/// The address stored on the user row must never diverge in case from the
/// address a lookup or an outbound verification / welcome mail resolves to. A
/// mixed-case signup ("Nice.Guy@Example.COM") that lands verbatim creates a row
/// that case-sensitive downstream consumers (e.g. the mokosh Next.js auth store,
/// which lowercases) never reconcile, so the verification mail is never matched
/// and the account stays stuck unverified. Every write to `users.email` funnels
/// through this helper, and every lookup already compares with `LOWER(email)`,
/// so the stored value and every comparison agree by construction.
///
/// Lowercasing only (no trimming): the read side (`LOWER($1)` in
/// `find_by_email` / `email_exists` / `email_reserved`, and `.to_lowercase()`
/// on the login rate-limit key) does not trim either, so trimming here would
/// let a stored value stop matching its own lookup.
pub fn normalize_email(email: &str) -> String {
    email.to_lowercase()
}

/// Data for creating a new user
#[derive(Debug, Clone)]
pub struct CreateUser {
    pub email: String,
    pub password_hash: Option<String>,
    pub role: UserRole,
}

/// Public user response (no sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub role: String,
    pub membership_status: String,
    pub price_locked: bool,
    pub locked_price_amount: Option<i32>,
    pub two_factor_enabled: bool,
    pub grace_period_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub membership_tier: String,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub lifetime_member: bool,
    /// BUNYIP-139: see [`User::first_name`].
    pub first_name: Option<String>,
    /// BUNYIP-139: see [`User::last_name`].
    pub last_name: Option<String>,
    /// BUNYIP-139: see [`User::phone`].
    pub phone: Option<String>,
    /// BUNYIP-408: see [`User::avatar_updated_at`]. Surfaced so bunyip-web can
    /// decide whether to render the avatar `<img>` (and with what cache-busting
    /// version) or fall back to initials.
    pub avatar_updated_at: Option<DateTime<Utc>>,
    /// BUNYIP-410 overhaul: whether this account is soft-deleted (suspended).
    /// Lets the admin users list distinguish suspended rows on the combined
    /// "All" view, where active and suspended users are interleaved.
    pub suspended: bool,
    /// BUNYIP-413: see [`User::is_super_admin`]. Surfaced so bunyip-web can
    /// render (or hide) the super-admin-only rate-limit / IP-ban controls.
    pub is_super_admin: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            role: user.role,
            membership_status: user.membership_status,
            price_locked: user.price_locked,
            locked_price_amount: user.locked_price_amount,
            two_factor_enabled: user.two_factor_enabled,
            grace_period_end: user.grace_period_end,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            membership_tier: user.membership_tier,
            trial_ends_at: user.trial_ends_at,
            lifetime_member: user.lifetime_member,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
            avatar_updated_at: user.avatar_updated_at,
            suspended: user.deleted_at.is_some(),
            is_super_admin: user.is_super_admin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// BUNYIP-325: every email is stored lowercased so a mixed-case signup
    /// cannot diverge from case-insensitive lookups and its verification mail.
    #[test]
    fn normalize_email_lowercases_mixed_case() {
        assert_eq!(
            normalize_email("Nice.Guy@Example.COM"),
            "nice.guy@example.com"
        );
        assert_eq!(normalize_email("ALLCAPS@X.IO"), "allcaps@x.io");
    }

    /// Idempotent: normalizing an already-lowercase address is a no-op, so
    /// re-running the backfill or re-writing a row never changes a clean value.
    #[test]
    fn normalize_email_is_idempotent_on_lowercase() {
        let once = normalize_email("already@lower.com");
        assert_eq!(once, "already@lower.com");
        assert_eq!(normalize_email(&once), once);
    }

    #[test]
    fn returning_member_is_not_eligible_for_a_second_trial() {
        // BUNYIP-291 AC5 (regression on BUNYIP-225): a first-timer gets the
        // signup trial; once has_used_trial is set (a prior trial checkout
        // completed), resubscribing after a cancel grants no new free trial.
        let mut u = test_user();
        u.has_used_trial = false;
        assert!(u.trial_eligible(), "first-timer should be trial-eligible");
        u.has_used_trial = true;
        assert!(
            !u.trial_eligible(),
            "returning member must not get a second free trial"
        );
    }

    fn test_user() -> User {
        User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            email_verified: true,
            password_hash: Some("hash".to_string()),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
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

    // -- UserRole --

    // -- MembershipStatus --

    // -- User methods --

    #[test]
    fn user_role_enum() {
        let user = test_user();
        assert_eq!(user.role_enum(), UserRole::Subscriber);

        let mut admin = test_user();
        admin.role = "admin".to_string();
        assert_eq!(admin.role_enum(), UserRole::Admin);
    }

    #[test]
    fn user_membership_status_enum() {
        let user = test_user();
        assert_eq!(user.membership_status_enum(), MembershipStatus::Active);
    }

    #[test]
    fn user_is_admin() {
        let user = test_user();
        assert!(!user.is_admin());

        let mut admin = test_user();
        admin.role = "admin".to_string();
        assert!(admin.is_admin());
    }

    #[test]
    fn user_has_active_membership() {
        let user = test_user();
        assert!(user.has_active_membership()); // "active"

        let mut canceled = test_user();
        canceled.membership_status = "canceled".to_string();
        assert!(!canceled.has_active_membership());

        let mut grace = test_user();
        grace.membership_status = "grace_period".to_string();
        assert!(grace.has_active_membership());
    }

    #[test]
    fn user_is_deleted() {
        let user = test_user();
        assert!(!user.is_deleted());

        let mut deleted = test_user();
        deleted.deleted_at = Some(Utc::now());
        assert!(deleted.is_deleted());
    }

    #[test]
    fn user_response_from_user() {
        let user = test_user();
        let id = user.id;
        let response = UserResponse::from(user);
        assert_eq!(response.id, id);
        assert_eq!(response.email, "test@example.com");
        assert_eq!(response.role, "subscriber");
    }

    // -- MembershipTier --

    fn user_with_tier(
        lifetime_member: bool,
        trial_ends_at: Option<DateTime<Utc>>,
        membership_tier: &str,
    ) -> User {
        let mut user = test_user();
        user.membership_status = "none".to_string();
        user.lifetime_member = lifetime_member;
        user.trial_ends_at = trial_ends_at;
        user.membership_tier = membership_tier.to_string();
        user
    }

    // -- is_access_allowed --

    #[test]
    fn access_allowed_for_admin() {
        let mut user = test_user();
        user.role = "admin".to_string();
        user.membership_status = "none".to_string();
        user.lifetime_member = false;
        user.trial_ends_at = None;
        assert!(user.is_access_allowed());
    }

    #[test]
    fn access_allowed_for_lifetime_member() {
        let user = user_with_tier(true, None, "lifetime");
        assert!(user.is_access_allowed());
    }

    #[test]
    fn access_allowed_for_free_member() {
        let user = user_with_tier(true, None, "free");
        assert!(user.is_access_allowed());
    }

    #[test]
    fn access_allowed_for_active_trial() {
        let future = Utc::now() + chrono::Duration::days(10);
        let user = user_with_tier(false, Some(future), "standard");
        assert!(user.is_access_allowed());
    }

    #[test]
    fn access_denied_for_expired_trial() {
        let past = Utc::now() - chrono::Duration::days(1);
        let user = user_with_tier(false, Some(past), "standard");
        assert!(!user.is_access_allowed());
    }

    #[test]
    fn access_allowed_for_active_membership() {
        let mut user = user_with_tier(false, None, "standard");
        user.membership_status = "active".to_string();
        assert!(user.is_access_allowed());
    }

    #[test]
    fn access_denied_for_no_membership_no_trial() {
        let user = user_with_tier(false, None, "standard");
        assert!(!user.is_access_allowed());
    }

    // -- Tier assignment logic (mirrors auth service) --
    // Tiers are assigned based on per-tier counts, not total user count.
    // This ensures slots fill correctly even if users existed before the tier system.

    fn tier_for_counts(
        lifetime_count: i64,
        early_adopter_count: i64,
        lifetime_slots: i64,
        early_adopter_slots: i64,
    ) -> MembershipTier {
        if lifetime_count < lifetime_slots {
            MembershipTier::Lifetime
        } else if early_adopter_count < early_adopter_slots {
            MembershipTier::EarlyAdopter
        } else {
            MembershipTier::Standard
        }
    }

    // Default thresholds: 5 lifetime slots, 5 early adopter slots

    #[test]
    fn tier_assignment_lifetime_slots_available() {
        // 4 lifetime assigned, slot still open
        assert_eq!(tier_for_counts(4, 0, 5, 5), MembershipTier::Lifetime);
    }

    #[test]
    fn tier_assignment_lifetime_slots_full() {
        // 5 lifetime assigned, falls through to early adopter
        assert_eq!(tier_for_counts(5, 0, 5, 5), MembershipTier::EarlyAdopter);
    }

    #[test]
    fn tier_assignment_early_adopter_slots_filling() {
        // lifetime full, 4 early adopter assigned
        assert_eq!(tier_for_counts(5, 4, 5, 5), MembershipTier::EarlyAdopter);
    }

    #[test]
    fn tier_assignment_all_slots_full() {
        // both tiers full
        assert_eq!(tier_for_counts(5, 5, 5, 5), MembershipTier::Standard);
    }

    #[test]
    fn tier_assignment_custom_thresholds() {
        // 3 lifetime slots, 7 early adopter slots
        assert_eq!(tier_for_counts(2, 0, 3, 7), MembershipTier::Lifetime);
        assert_eq!(tier_for_counts(3, 0, 3, 7), MembershipTier::EarlyAdopter);
        assert_eq!(tier_for_counts(3, 6, 3, 7), MembershipTier::EarlyAdopter);
        assert_eq!(tier_for_counts(3, 7, 3, 7), MembershipTier::Standard);
    }

    #[test]
    fn tier_assignment_existing_users_dont_consume_slots() {
        // 100 standard users exist but 0 lifetime assigned — lifetime still available
        assert_eq!(tier_for_counts(0, 0, 5, 5), MembershipTier::Lifetime);
    }
}
