//! BUNYIP-692: org-tier catalogue service.
//!
//! Every method gates on `orgs_enabled` and returns
//! [`AppError::not_found`] when the flag is off, matching BUNYIP-493's
//! "off means INVISIBLE" rule and the sibling
//! [`crate::services::OrganizationsService`] shape.
//!
//! The service accepts `orgs_enabled` as an argument so the handler
//! resolves the tier-config lock once per request.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    validate_seats, validate_stripe_price_id, validate_tier_name, validate_visibility,
    CreateOrgPricingTierRequest, OrgPricingTier, PublicOrgPricingTier,
    ReorderOrgPricingTiersRequest, UpdateOrgPricingTierRequest,
};
use crate::repositories::{OrgPricingRepository, OrganizationRepository};

pub struct OrgPricingService;

impl OrgPricingService {
    /// `GET /v1/pricing/orgs`. Returns `[]` when the flag is off so a
    /// caller can render blind without knowing the flag itself.
    pub async fn public_list(
        pool: &PgPool,
        orgs_enabled: bool,
    ) -> Result<Vec<PublicOrgPricingTier>, AppError> {
        if !orgs_enabled {
            return Ok(Vec::new());
        }
        let rows = OrgPricingRepository::list_public(pool).await?;
        Ok(rows.iter().map(PublicOrgPricingTier::from).collect())
    }

    /// Admin `GET /v1/admin/pricing/orgs`. Every row including hidden.
    pub async fn admin_list(
        pool: &PgPool,
        orgs_enabled: bool,
    ) -> Result<Vec<OrgPricingTier>, AppError> {
        gate(orgs_enabled)?;
        OrgPricingRepository::list_all(pool).await
    }

    pub async fn admin_create(
        pool: &PgPool,
        orgs_enabled: bool,
        req: CreateOrgPricingTierRequest,
    ) -> Result<OrgPricingTier, AppError> {
        gate(orgs_enabled)?;
        let name =
            validate_tier_name(&req.name).map_err(|msg| AppError::validation("name", msg))?;
        let stripe_price_id = validate_stripe_price_id(&req.stripe_price_id)
            .map_err(|msg| AppError::validation("stripe_price_id", msg))?;
        if !validate_visibility(&req.visibility) {
            return Err(AppError::validation(
                "visibility",
                "visibility must be 'public' or 'hidden'",
            ));
        }
        validate_seats(req.included_seats, req.seat_cap)
            .map_err(|msg| AppError::validation("included_seats", msg))?;
        OrgPricingRepository::create(
            pool,
            &name,
            &stripe_price_id,
            req.included_seats,
            req.seat_cap,
            &req.visibility,
            req.sort_order,
        )
        .await
    }

    pub async fn admin_update(
        pool: &PgPool,
        orgs_enabled: bool,
        id: Uuid,
        req: UpdateOrgPricingTierRequest,
    ) -> Result<OrgPricingTier, AppError> {
        gate(orgs_enabled)?;
        // Existence check first, so a 404 wins over a partial-validation
        // error on a row that does not exist.
        let existing = OrgPricingRepository::find_by_id(pool, id)
            .await?
            .ok_or_else(|| AppError::not_found("Org pricing tier"))?;

        let name = match req.name.as_deref() {
            Some(n) => {
                Some(validate_tier_name(n).map_err(|msg| AppError::validation("name", msg))?)
            }
            None => None,
        };
        let stripe_price_id = match req.stripe_price_id.as_deref() {
            Some(id) => Some(
                validate_stripe_price_id(id)
                    .map_err(|msg| AppError::validation("stripe_price_id", msg))?,
            ),
            None => None,
        };
        if let Some(v) = req.visibility.as_deref() {
            if !validate_visibility(v) {
                return Err(AppError::validation(
                    "visibility",
                    "visibility must be 'public' or 'hidden'",
                ));
            }
        }
        // Seat validation runs against the RESOLVED pair (updated field
        // else existing value), so a caller who moves only one half still
        // gets caught if the resulting pair is invalid.
        let resolved_included = req.included_seats.unwrap_or(existing.included_seats);
        let resolved_cap = match req.seat_cap {
            Some(v) => v,
            None => existing.seat_cap,
        };
        validate_seats(resolved_included, resolved_cap)
            .map_err(|msg| AppError::validation("included_seats", msg))?;

        OrgPricingRepository::update(
            pool,
            id,
            name.as_deref(),
            stripe_price_id.as_deref(),
            req.included_seats,
            req.seat_cap,
            req.visibility.as_deref(),
            req.sort_order,
        )
        .await
    }

    pub async fn admin_delete(pool: &PgPool, orgs_enabled: bool, id: Uuid) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        let deleted = OrgPricingRepository::delete(pool, id).await?;
        if !deleted {
            return Err(AppError::not_found("Org pricing tier"));
        }
        Ok(())
    }

    pub async fn admin_reorder(
        pool: &PgPool,
        orgs_enabled: bool,
        req: ReorderOrgPricingTiersRequest,
    ) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        if req.ids.is_empty() {
            return Ok(());
        }
        OrgPricingRepository::reorder(pool, &req.ids).await
    }

    /// `PUT /v1/organization/tier` - the caller (org owner) picks a tier.
    ///
    /// Refuses a `hidden` tier when the caller is not currently on it, so
    /// an admin can retire a tier from the catalogue without stranding orgs
    /// already using it.
    pub async fn set_organization_tier(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        org_tier_id: Uuid,
    ) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;

        let tier = OrgPricingRepository::find_by_id(pool, org_tier_id)
            .await?
            .ok_or_else(|| AppError::not_found("Org pricing tier"))?;

        if tier.visibility == "hidden" {
            let current = OrgPricingRepository::get_organization_tier(pool, org.id).await?;
            if current != Some(tier.id) {
                return Err(AppError::not_found("Org pricing tier"));
            }
        }

        OrgPricingRepository::set_organization_tier(pool, org.id, Some(tier.id)).await?;
        Ok(())
    }

    /// `DELETE /v1/organization/tier` - the caller clears their org's
    /// tier. BUNYIP-693 refuses to subscribe against a cleared row, so
    /// clearing declares "do not bill me until I pick again".
    pub async fn clear_organization_tier(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<(), AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        OrgPricingRepository::set_organization_tier(pool, org.id, None).await?;
        Ok(())
    }
}

fn gate(orgs_enabled: bool) -> Result<(), AppError> {
    if orgs_enabled {
        Ok(())
    } else {
        // Matches the sibling `services::organizations::gate`.
        Err(AppError::not_found("Organization"))
    }
}
