//! Admin-managed product branding (BUNYIP-561).
//!
//! The product name, tagline, meta description and Open Graph image are a
//! singleton database row edited from the admin panel, not literals compiled
//! into the binaries. Resolution is stated once, here:
//!
//! - `brand_name` is the row value when non-empty, else the bootstrap
//!   `APP_NAME` (a database that has never been branded);
//! - `tagline`, `meta_description` and `og_image_url` are the row value when
//!   non-empty, else EMPTY, and empty means the markup is OMITTED. No literal
//!   is ever substituted: substituting one would put the copy back in the
//!   binary, which is the defect.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Database row for the `branding` singleton table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BrandingRow {
    pub id: i32,
    pub brand_name: String,
    pub tagline: String,
    pub meta_description: String,
    pub og_image_url: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// The four resolved branding values, as served by `GET /v1/branding` and
/// rendered by bunyip-web. An empty field means "omit the markup", never
/// "substitute a default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branding {
    pub brand_name: String,
    pub tagline: String,
    pub meta_description: String,
    pub og_image_url: String,
}

/// Admin view: the resolved values plus the attribution the email and Stripe
/// config rows carry.
#[derive(Debug, Clone, Serialize)]
pub struct BrandingResponse {
    #[serde(flatten)]
    pub branding: Branding,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// Request body for `PUT /v1/admin/branding`. Every field is a full
/// replacement, not a COALESCE: clearing a field to empty is the way an admin
/// removes a tagline, description or Open Graph image, so "absent" and "empty"
/// must stay distinguishable.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateBrandingRequest {
    #[serde(default)]
    pub brand_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub meta_description: String,
    #[serde(default)]
    pub og_image_url: String,
}

/// Length caps. Generous enough for any real brand, tight enough that a paste
/// accident does not become the `<title>` of every page.
pub const MAX_BRAND_NAME_LEN: usize = 120;
pub const MAX_TAGLINE_LEN: usize = 200;
/// Search engines truncate a description past roughly 160 characters; the cap
/// is double that so a longer sentence is a choice rather than a rejection.
pub const MAX_META_DESCRIPTION_LEN: usize = 320;
pub const MAX_OG_IMAGE_URL_LEN: usize = 2048;

/// A rejected branding save: the field that failed and the message the admin
/// form renders. Pure, so the caller maps it to one 4xx (never a 5xx, which
/// bunyip-web collapses into the generic error line, BUNYIP-506).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandingFieldError {
    pub field: &'static str,
    pub message: String,
}

/// Validate a branding update and return the trimmed values to persist.
///
/// `og_image_url` must be absolute (`http://` or `https://`): it is rendered as
/// `og:image`, which every consumer fetches out of band with no page context,
/// so a relative path resolves against the wrong origin and shows nothing.
pub fn validate_branding(
    req: &UpdateBrandingRequest,
) -> Result<UpdateBrandingRequest, BrandingFieldError> {
    let brand_name = req.brand_name.trim();
    let tagline = req.tagline.trim();
    let meta_description = req.meta_description.trim();
    let og_image_url = req.og_image_url.trim();

    let too_long = |field: &'static str, label: &str, value: &str, max: usize| {
        (value.chars().count() > max).then(|| BrandingFieldError {
            field,
            message: format!("{label} must be {max} characters or fewer."),
        })
    };

    if let Some(e) = too_long("brand_name", "Brand name", brand_name, MAX_BRAND_NAME_LEN) {
        return Err(e);
    }
    if let Some(e) = too_long("tagline", "Tagline", tagline, MAX_TAGLINE_LEN) {
        return Err(e);
    }
    if let Some(e) = too_long(
        "meta_description",
        "Meta description",
        meta_description,
        MAX_META_DESCRIPTION_LEN,
    ) {
        return Err(e);
    }
    if let Some(e) = too_long(
        "og_image_url",
        "Open Graph image URL",
        og_image_url,
        MAX_OG_IMAGE_URL_LEN,
    ) {
        return Err(e);
    }
    let absolute = og_image_url.starts_with("https://") || og_image_url.starts_with("http://");
    if !og_image_url.is_empty() && !absolute {
        return Err(BrandingFieldError {
            field: "og_image_url",
            message: "Open Graph image URL must be absolute and start with https:// or http://."
                .to_string(),
        });
    }

    Ok(UpdateBrandingRequest {
        brand_name: brand_name.to_string(),
        tagline: tagline.to_string(),
        meta_description: meta_description.to_string(),
        og_image_url: og_image_url.to_string(),
    })
}

/// Process-wide cache of the resolved branding, refreshed on an admin `PUT` and
/// on a TTL by the background task `main` spawns.
///
/// `EmailService` and `TotpService` read the brand name from here rather than
/// from a value fixed at construction, so an admin rename reaches email
/// subjects and new TOTP enrolments without a restart.
pub struct BrandingCache {
    /// Bootstrap default for `brand_name` when the row is empty: bunyip-api's
    /// `APP_NAME`. Only this one field has a fallback; the other three omit.
    fallback_brand_name: String,
    slot: RwLock<Arc<Branding>>,
}

impl BrandingCache {
    /// A cache holding the unbranded state: the row has never been read, so
    /// `brand_name` is the bootstrap default and everything else is empty.
    pub fn new(fallback_brand_name: impl Into<String>) -> Self {
        let fallback_brand_name = fallback_brand_name.into();
        let initial = Branding {
            brand_name: fallback_brand_name.clone(),
            ..Branding::default()
        };
        Self {
            fallback_brand_name,
            slot: RwLock::new(Arc::new(initial)),
        }
    }

    /// Resolve a row against the bootstrap default without storing it.
    pub fn resolve(&self, row: &BrandingRow) -> Branding {
        let brand_name = match row.brand_name.trim() {
            "" => self.fallback_brand_name.clone(),
            name => name.to_string(),
        };
        Branding {
            brand_name,
            tagline: row.tagline.trim().to_string(),
            meta_description: row.meta_description.trim().to_string(),
            og_image_url: row.og_image_url.trim().to_string(),
        }
    }

    /// Resolve `row` and make it the value every reader sees.
    pub fn store(&self, row: &BrandingRow) -> Arc<Branding> {
        let resolved = Arc::new(self.resolve(row));
        // A poisoned lock means a writer panicked; the data is structurally
        // intact, so recover through the poison rather than taking the process
        // down over a branding string.
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = Arc::clone(&resolved);
        resolved
    }

    /// The current resolved branding.
    pub fn get(&self) -> Arc<Branding> {
        Arc::clone(&self.slot.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// The resolved product name, for email subjects and the TOTP issuer.
    pub fn brand_name(&self) -> String {
        self.get().brand_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(brand_name: &str, tagline: &str, meta: &str, og: &str) -> BrandingRow {
        BrandingRow {
            id: 1,
            brand_name: brand_name.to_string(),
            tagline: tagline.to_string(),
            meta_description: meta.to_string(),
            og_image_url: og.to_string(),
            updated_at: Utc::now(),
            updated_by: None,
        }
    }

    /// The whole point of the record: an empty `brand_name` falls back to
    /// `APP_NAME`, and the other three stay empty so their markup is omitted
    /// rather than filled with a compiled-in literal.
    #[test]
    fn an_empty_row_resolves_the_name_to_app_name_and_omits_the_rest() {
        let cache = BrandingCache::new("PSA Systems");
        let resolved = cache.resolve(&row("", "", "", ""));
        assert_eq!(resolved.brand_name, "PSA Systems");
        assert_eq!(resolved.tagline, "");
        assert_eq!(resolved.meta_description, "");
        assert_eq!(resolved.og_image_url, "");
    }

    /// A whitespace-only name is empty for this purpose; it must not render as
    /// a blank product name in the browser title.
    #[test]
    fn a_blank_brand_name_still_falls_back() {
        let cache = BrandingCache::new("PSA Systems");
        assert_eq!(
            cache.resolve(&row("   ", "", "", "")).brand_name,
            "PSA Systems"
        );
    }

    #[test]
    fn a_populated_row_wins_over_the_bootstrap_default() {
        let cache = BrandingCache::new("PSA Systems");
        let resolved = cache.resolve(&row(
            "Acme",
            "Surfaces what matters.",
            "Acme does things.",
            "https://acme.test/card.png",
        ));
        assert_eq!(resolved.brand_name, "Acme");
        assert_eq!(resolved.tagline, "Surfaces what matters.");
        assert_eq!(resolved.meta_description, "Acme does things.");
        assert_eq!(resolved.og_image_url, "https://acme.test/card.png");
    }

    #[test]
    fn store_publishes_to_every_reader() {
        let cache = BrandingCache::new("PSA Systems");
        assert_eq!(cache.brand_name(), "PSA Systems");
        cache.store(&row("Acme", "", "", ""));
        assert_eq!(cache.brand_name(), "Acme");
        assert_eq!(cache.get().brand_name, "Acme");
    }

    #[test]
    fn validation_trims_and_accepts_an_empty_record() {
        let ok = validate_branding(&UpdateBrandingRequest {
            brand_name: "  Acme  ".into(),
            ..UpdateBrandingRequest::default()
        })
        .expect("an empty record is a legitimate save: it clears the brand");
        assert_eq!(ok.brand_name, "Acme");
        assert_eq!(ok.og_image_url, "");
    }

    #[test]
    fn validation_rejects_an_over_length_name() {
        let err = validate_branding(&UpdateBrandingRequest {
            brand_name: "x".repeat(MAX_BRAND_NAME_LEN + 1),
            ..UpdateBrandingRequest::default()
        })
        .expect_err("over the cap");
        assert_eq!(err.field, "brand_name");
        assert!(err.message.contains("120"), "{}", err.message);
    }

    #[test]
    fn validation_rejects_an_over_length_description() {
        let err = validate_branding(&UpdateBrandingRequest {
            meta_description: "x".repeat(MAX_META_DESCRIPTION_LEN + 1),
            ..UpdateBrandingRequest::default()
        })
        .expect_err("over the cap");
        assert_eq!(err.field, "meta_description");
    }

    /// `og:image` is fetched with no page context, so a relative path resolves
    /// against the consumer's origin and shows nothing.
    #[test]
    fn validation_rejects_a_relative_og_image_url() {
        for candidate in ["/assets/card.png", "assets/card.png", "//cdn.test/c.png"] {
            let err = validate_branding(&UpdateBrandingRequest {
                og_image_url: candidate.into(),
                ..UpdateBrandingRequest::default()
            })
            .expect_err("a relative og:image is rejected");
            assert_eq!(err.field, "og_image_url");
        }
        assert!(validate_branding(&UpdateBrandingRequest {
            og_image_url: "https://cdn.test/card.png".into(),
            ..UpdateBrandingRequest::default()
        })
        .is_ok());
    }
}
