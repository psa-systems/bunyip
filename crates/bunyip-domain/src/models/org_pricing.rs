//! BUNYIP-692 [BUNYIP-626 followup]: org-tier pricing catalogue models.
//!
//! Separate table from the per-user `pricing` catalogue because the two
//! shapes carry different columns; see the migration comment. Every org
//! (BUNYIP-672) picks a tier row through `PUT /v1/organization/tier`, and
//! BUNYIP-693's seat-based subscription bills against `stripe_price_id`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Org-tier row, as it lives in the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrgPricingTier {
    pub id: Uuid,
    pub name: String,
    pub stripe_price_id: String,
    pub included_seats: i32,
    pub seat_cap: Option<i32>,
    pub visibility: String,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One tier as the public catalogue exposes it. The Stripe id and admin
/// audit fields (`created_at`, `updated_at`) are dropped because a public
/// visitor has no reason to see either; the price a card renders comes
/// from a live Stripe lookup keyed on `stripe_price_id` at admin time and
/// cached by the marketing site, matching the shape user tiers use.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PublicOrgPricingTier {
    pub id: Uuid,
    pub name: String,
    pub stripe_price_id: String,
    pub included_seats: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat_cap: Option<i32>,
}

impl From<&OrgPricingTier> for PublicOrgPricingTier {
    fn from(row: &OrgPricingTier) -> Self {
        Self {
            id: row.id,
            name: row.name.clone(),
            stripe_price_id: row.stripe_price_id.clone(),
            included_seats: row.included_seats,
            seat_cap: row.seat_cap,
        }
    }
}

/// Body for `POST /v1/admin/pricing/orgs`.
#[derive(Debug, Deserialize)]
pub struct CreateOrgPricingTierRequest {
    pub name: String,
    pub stripe_price_id: String,
    #[serde(default)]
    pub included_seats: i32,
    #[serde(default)]
    pub seat_cap: Option<i32>,
    #[serde(default = "default_visibility")]
    pub visibility: String,
    #[serde(default)]
    pub sort_order: i32,
}

/// Body for `PUT /v1/admin/pricing/orgs/{id}`. Every field is optional so a
/// partial update leaves the rest alone; that matches how the admin CRUD on
/// the user pricing side handles partial edits.
#[derive(Debug, Deserialize, Default)]
pub struct UpdateOrgPricingTierRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub stripe_price_id: Option<String>,
    #[serde(default)]
    pub included_seats: Option<i32>,
    #[serde(default)]
    pub seat_cap: Option<Option<i32>>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub sort_order: Option<i32>,
}

/// Body for `PUT /v1/admin/pricing/orgs/reorder`. Ids in the order the admin
/// picked; the service writes each `sort_order` to its index in the list.
#[derive(Debug, Deserialize)]
pub struct ReorderOrgPricingTiersRequest {
    pub ids: Vec<Uuid>,
}

/// Body for `PUT /v1/organization/tier`. Setting the tier is the owner's
/// pick; `None` (via the sibling DELETE) clears it. BUNYIP-693 refuses to
/// subscribe against a cleared row, so an owner clearing their tier is
/// declaring they will not be billed until they pick again.
#[derive(Debug, Deserialize)]
pub struct SetOrganizationTierRequest {
    pub org_tier_id: Uuid,
}

fn default_visibility() -> String {
    "public".to_string()
}

pub const VALID_VISIBILITIES: &[&str] = &["public", "hidden"];

pub fn validate_visibility(v: &str) -> bool {
    VALID_VISIBILITIES.contains(&v)
}

/// Validate the shape of a tier name. Trimmed, non-empty, <=80 chars, no
/// control characters. Kept separate from `validate_name` on the org table
/// because the caps and message differ.
pub fn validate_tier_name(name: &str) -> Result<String, &'static str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("name cannot be empty");
    }
    if trimmed.chars().count() > 80 {
        return Err("name cannot exceed 80 characters");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("name cannot contain control characters");
    }
    Ok(trimmed.to_string())
}

/// Validate a Stripe price id. Stripe's public shape is `price_...` (case-
/// sensitive), a short prefix followed by alphanumerics. This does not
/// contact Stripe; the shape check is enough to reject obvious typos before
/// the admin write reaches the UNIQUE constraint. A real price that Stripe
/// does not recognise still writes; the admin subscription attempt in
/// BUNYIP-693 is what surfaces that.
pub fn validate_stripe_price_id(id: &str) -> Result<String, &'static str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err("stripe_price_id cannot be empty");
    }
    if !trimmed.starts_with("price_") {
        return Err("stripe_price_id must begin with 'price_'");
    }
    if trimmed.chars().count() > 128 {
        return Err("stripe_price_id cannot exceed 128 characters");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("stripe_price_id may only contain ASCII letters, digits and underscores");
    }
    Ok(trimmed.to_string())
}

/// Validate `included_seats` / `seat_cap` together, matching the CHECK
/// constraints on the table.
pub fn validate_seats(included_seats: i32, seat_cap: Option<i32>) -> Result<(), &'static str> {
    if included_seats < 0 {
        return Err("included_seats cannot be negative");
    }
    if let Some(cap) = seat_cap {
        if cap < included_seats {
            return Err("seat_cap cannot be less than included_seats");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tier_name_accepts_a_trimmed_string() {
        assert_eq!(validate_tier_name("  Standard  ").unwrap(), "Standard");
    }

    #[test]
    fn validate_tier_name_refuses_empty_and_control_characters() {
        assert!(validate_tier_name("").is_err());
        assert!(validate_tier_name("   ").is_err());
        assert!(validate_tier_name("Standard\0").is_err());
    }

    #[test]
    fn validate_stripe_price_id_accepts_a_realistic_shape() {
        assert_eq!(
            validate_stripe_price_id("price_1PabcXYZ12345").unwrap(),
            "price_1PabcXYZ12345"
        );
    }

    #[test]
    fn validate_stripe_price_id_refuses_the_wrong_prefix_or_bad_chars() {
        assert!(validate_stripe_price_id("").is_err());
        assert!(validate_stripe_price_id("prod_1234").is_err());
        assert!(validate_stripe_price_id("price 1234").is_err());
        assert!(validate_stripe_price_id("price_hi!").is_err());
    }

    #[test]
    fn validate_visibility_accepts_public_and_hidden() {
        assert!(validate_visibility("public"));
        assert!(validate_visibility("hidden"));
        assert!(!validate_visibility(""));
        assert!(!validate_visibility("PUBLIC"));
        assert!(!validate_visibility("private"));
    }

    #[test]
    fn validate_seats_matches_the_check_constraints() {
        assert!(validate_seats(0, None).is_ok());
        assert!(validate_seats(5, Some(10)).is_ok());
        assert!(validate_seats(5, Some(5)).is_ok());
        assert!(validate_seats(-1, None).is_err());
        assert!(validate_seats(5, Some(4)).is_err());
    }

    #[test]
    fn valid_visibilities_list_matches_the_check_constraint() {
        assert_eq!(VALID_VISIBILITIES, ["public", "hidden"]);
    }
}
