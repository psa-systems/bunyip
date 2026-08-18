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
//!
//! BUNYIP-560 extends the record to the brand-carrying ASSETS and the palette
//! under the same rule. `theme_css`, `theme_color_light` and `theme_color_dark`
//! are the row value or EMPTY; the mark, favicon and mascot are rows in
//! `branding_assets` whose presence is reported as a version string
//! (`*_updated_at`, or empty when the slot is unset). An empty version means the
//! caller falls back to the committed file under `bunyip-web/assets/` (the
//! favicon set) or renders nothing at all (the mascot, the mark image, both
//! `theme-color` metas, the `:root` block).

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
    /// BUNYIP-560: raw CSS custom-property declarations for the brand ramp.
    pub theme_css: String,
    /// BUNYIP-560: the two `<meta name="theme-color">` values.
    pub theme_color_light: String,
    pub theme_color_dark: String,
    /// BUNYIP-560: "this asset exists, and this is its version" markers, kept
    /// on the singleton row (mirroring `users.avatar_updated_at`) so the hot
    /// `GET /v1/branding` path learns which slots are filled without ever
    /// transferring a BYTEA. Written in the same transaction as the
    /// `branding_assets` rows.
    pub mark_updated_at: Option<DateTime<Utc>>,
    pub favicon_updated_at: Option<DateTime<Utc>>,
    pub mascot_updated_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// The resolved branding values, as served by `GET /v1/branding` and rendered
/// by bunyip-web. An empty field means "omit the markup", never "substitute a
/// default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branding {
    pub brand_name: String,
    pub tagline: String,
    pub meta_description: String,
    pub og_image_url: String,
    /// BUNYIP-560: the palette. Empty means the `:root` block / the
    /// `theme-color` meta is omitted.
    pub theme_css: String,
    pub theme_color_light: String,
    pub theme_color_dark: String,
    /// BUNYIP-560: the asset slots, as a version string the client hangs off
    /// its `<img src>` as a cache buster. Empty means the slot is unset.
    pub mark_version: String,
    pub favicon_version: String,
    pub mascot_version: String,
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
    #[serde(default)]
    pub theme_css: String,
    #[serde(default)]
    pub theme_color_light: String,
    #[serde(default)]
    pub theme_color_dark: String,
}

/// Length caps. Generous enough for any real brand, tight enough that a paste
/// accident does not become the `<title>` of every page.
pub const MAX_BRAND_NAME_LEN: usize = 120;
pub const MAX_TAGLINE_LEN: usize = 200;
/// Search engines truncate a description past roughly 160 characters; the cap
/// is double that so a longer sentence is a choice rather than a rejection.
pub const MAX_META_DESCRIPTION_LEN: usize = 320;
pub const MAX_OG_IMAGE_URL_LEN: usize = 2048;
/// BUNYIP-560: a full custom-property ramp is a few hundred bytes; 4 KiB is a
/// paste accident, not a palette.
pub const MAX_THEME_CSS_LEN: usize = 4096;
/// `#rgb`, `#rrggbb` or `#rrggbbaa`.
pub const MAX_THEME_COLOR_LEN: usize = 9;

/// BUNYIP-560: is this a CSS hex colour (`#rgb`, `#rrggbb`, `#rrggbbaa`)?
///
/// `theme-color` is exactly a colour, and hex is the one notation every browser
/// that honours the meta accepts, so the field is restricted to it rather than
/// to "some string that reaches an attribute".
fn is_hex_color(value: &str) -> bool {
    let Some(digits) = value.strip_prefix('#') else {
        return false;
    };
    matches!(digits.len(), 3 | 4 | 6 | 8) && digits.chars().all(|c| c.is_ascii_hexdigit())
}

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
    let theme_css = req.theme_css.trim();
    let theme_color_light = req.theme_color_light.trim();
    let theme_color_dark = req.theme_color_dark.trim();

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

    if let Some(e) = too_long("theme_css", "Theme CSS", theme_css, MAX_THEME_CSS_LEN) {
        return Err(e);
    }
    // The value is emitted verbatim inside a `<style>` element, so an angle
    // bracket is the one character that could close it and start markup. There
    // is no legitimate `<` or `>` in a custom-property declaration list.
    if theme_css.contains('<') || theme_css.contains('>') {
        return Err(BrandingFieldError {
            field: "theme_css",
            message: "Theme CSS must not contain < or >: it is emitted inside a style element."
                .to_string(),
        });
    }
    for (field, label, value) in [
        ("theme_color_light", "Light theme colour", theme_color_light),
        ("theme_color_dark", "Dark theme colour", theme_color_dark),
    ] {
        if !value.is_empty() && !is_hex_color(value) {
            return Err(BrandingFieldError {
                field,
                message: format!(
                    "{label} must be a hex colour such as #2f4e2e, or blank to omit the meta tag."
                ),
            });
        }
    }

    Ok(UpdateBrandingRequest {
        brand_name: brand_name.to_string(),
        tagline: tagline.to_string(),
        meta_description: meta_description.to_string(),
        og_image_url: og_image_url.to_string(),
        theme_css: theme_css.to_string(),
        theme_color_light: theme_color_light.to_string(),
        theme_color_dark: theme_color_dark.to_string(),
    })
}

/// BUNYIP-560: one uploadable brand asset slot. The favicon slot is the odd one
/// out: the admin uploads ONE source and the whole icon set is derived from it,
/// so the slot's stored rows are `favicon-source` plus [`DERIVED_FAVICONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrandingAssetSlot {
    Mark,
    Favicon,
    Mascot,
}

impl BrandingAssetSlot {
    /// The slot name in the URL (`/v1/branding/assets/...` is keyed by storage
    /// kind; the admin routes are keyed by slot).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mark => "mark",
            Self::Favicon => "favicon",
            Self::Mascot => "mascot",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mark" => Some(Self::Mark),
            "favicon" => Some(Self::Favicon),
            "mascot" => Some(Self::Mascot),
            _ => None,
        }
    }

    /// Every storage key this slot owns. Clearing the slot deletes all of them,
    /// so a derived icon can never outlive the source it came from.
    pub fn storage_kinds(self) -> Vec<&'static str> {
        match self {
            Self::Mark => vec!["mark"],
            Self::Mascot => vec!["mascot"],
            Self::Favicon => {
                let mut kinds = vec![FAVICON_SOURCE_KIND];
                kinds.extend(DERIVED_FAVICONS.iter().map(|d| d.kind));
                kinds
            }
        }
    }

    /// The `branding.<slot>_updated_at` column this slot maintains.
    pub const fn version_column(self) -> &'static str {
        match self {
            Self::Mark => "mark_updated_at",
            Self::Favicon => "favicon_updated_at",
            Self::Mascot => "mascot_updated_at",
        }
    }
}

/// The storage key holding exactly what the admin uploaded for the favicon
/// slot. Never referenced from markup; kept so a later derivation change can
/// re-derive without asking the admin to upload again.
pub const FAVICON_SOURCE_KIND: &str = "favicon-source";

/// BUNYIP-560: one derived favicon. `size` is the square edge in pixels; `kind`
/// is its storage key and the last segment of its URL.
#[derive(Debug, Clone, Copy)]
pub struct DerivedFavicon {
    pub kind: &'static str,
    pub size: u32,
    pub mime: &'static str,
}

/// The icon set derived from one uploaded source, matching the committed
/// fallback set under `bunyip-web/assets/` one for one. The 512 is PNG here
/// (the committed fallback is WebP, hand-tuned for the byte budget of art this
/// repo ships); a derived icon is admin-uploaded, so a predictable encoder
/// every browser decodes beats a smaller file.
pub const DERIVED_FAVICONS: &[DerivedFavicon] = &[
    DerivedFavicon {
        kind: "favicon-16",
        size: 16,
        mime: "image/png",
    },
    DerivedFavicon {
        kind: "favicon-32",
        size: 32,
        mime: "image/png",
    },
    DerivedFavicon {
        kind: "favicon-48",
        size: 48,
        mime: "image/png",
    },
    DerivedFavicon {
        kind: "favicon-192",
        size: 192,
        mime: "image/png",
    },
    DerivedFavicon {
        kind: "favicon-512",
        size: 512,
        mime: "image/png",
    },
    // iOS home-screen icon; 180 is the size Apple asks for.
    DerivedFavicon {
        kind: "apple-touch-icon",
        size: 180,
        mime: "image/png",
    },
    // The `/favicon.ico` probe. One 48x48 frame: the ICO container exists for
    // the browsers that only look for this URL, not for a size ladder.
    DerivedFavicon {
        kind: "favicon-ico",
        size: 48,
        mime: "image/x-icon",
    },
];

/// Every storage key that can be served from `GET /v1/branding/assets/{kind}`.
/// A key outside this set is a 404 before any query runs, so the path parameter
/// can never name an arbitrary row.
pub fn is_servable_asset_kind(kind: &str) -> bool {
    kind == "mark"
        || kind == "mascot"
        || kind == FAVICON_SOURCE_KIND
        || DERIVED_FAVICONS.iter().any(|d| d.kind == kind)
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
        // BUNYIP-560: an unset asset slot resolves to an EMPTY version, which is
        // how every reader tells "no asset" from "this asset, at this version".
        let version = |at: Option<DateTime<Utc>>| {
            at.map(|t| t.timestamp_millis().to_string())
                .unwrap_or_default()
        };
        Branding {
            brand_name,
            tagline: row.tagline.trim().to_string(),
            meta_description: row.meta_description.trim().to_string(),
            og_image_url: row.og_image_url.trim().to_string(),
            theme_css: row.theme_css.trim().to_string(),
            theme_color_light: row.theme_color_light.trim().to_string(),
            theme_color_dark: row.theme_color_dark.trim().to_string(),
            mark_version: version(row.mark_updated_at),
            favicon_version: version(row.favicon_updated_at),
            mascot_version: version(row.mascot_updated_at),
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
            theme_css: String::new(),
            theme_color_light: String::new(),
            theme_color_dark: String::new(),
            mark_updated_at: None,
            favicon_updated_at: None,
            mascot_updated_at: None,
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

    // --- BUNYIP-560: the palette and the asset slots ------------------------

    /// An unset slot resolves to an EMPTY version, which is the signal every
    /// reader uses to fall back (the favicon set) or render nothing (the mark
    /// image, the mascot). A set slot carries a version so the browser refetches
    /// after a re-upload instead of showing the previous logo forever.
    #[test]
    fn an_unset_asset_slot_resolves_to_an_empty_version() {
        let cache = BrandingCache::new("PSA Systems");
        let resolved = cache.resolve(&row("", "", "", ""));
        assert_eq!(resolved.mark_version, "");
        assert_eq!(resolved.favicon_version, "");
        assert_eq!(resolved.mascot_version, "");

        let mut set = row("", "", "", "");
        set.favicon_updated_at = Some(Utc::now());
        let resolved = cache.resolve(&set);
        assert!(!resolved.favicon_version.is_empty());
        assert_eq!(resolved.mark_version, "", "one slot does not fill another");
    }

    /// The palette follows the same empty-means-omit rule as the copy: nothing
    /// substitutes bunyip's own colours when the record has none.
    #[test]
    fn an_unbranded_palette_stays_empty() {
        let cache = BrandingCache::new("PSA Systems");
        let resolved = cache.resolve(&row("", "", "", ""));
        assert_eq!(resolved.theme_css, "");
        assert_eq!(resolved.theme_color_light, "");
        assert_eq!(resolved.theme_color_dark, "");
    }

    /// The `theme-color` metas are attribute values and the CSS block is
    /// emitted verbatim inside `<style>`, so both are validated rather than
    /// trusted: a rejected save writes nothing and the form renders the reason.
    #[test]
    fn validation_rejects_a_non_hex_theme_color_and_accepts_every_hex_form() {
        for bad in ["reed-green", "rgb(1,2,3)", "#12345", "2f4e2e", "#ggghhh"] {
            let err = validate_branding(&UpdateBrandingRequest {
                theme_color_light: bad.into(),
                ..UpdateBrandingRequest::default()
            })
            .expect_err("a non-hex theme colour is rejected");
            assert_eq!(err.field, "theme_color_light");
            assert!(!err.message.is_empty());
        }
        for good in ["#fff", "#ffff", "#2f4e2e", "#2f4e2eff", ""] {
            assert!(
                validate_branding(&UpdateBrandingRequest {
                    theme_color_dark: good.into(),
                    ..UpdateBrandingRequest::default()
                })
                .is_ok(),
                "{good} is a legitimate value"
            );
        }
    }

    /// `theme_css` reaches the page unescaped (it IS CSS), so the one character
    /// that could close the element and start markup is refused.
    #[test]
    fn validation_rejects_markup_in_the_theme_css() {
        let err = validate_branding(&UpdateBrandingRequest {
            theme_css: "--skin-primary-500:#123456}</style><script>alert(1)</script>".into(),
            ..UpdateBrandingRequest::default()
        })
        .expect_err("angle brackets are refused");
        assert_eq!(err.field, "theme_css");

        let err = validate_branding(&UpdateBrandingRequest {
            theme_css: "x".repeat(MAX_THEME_CSS_LEN + 1),
            ..UpdateBrandingRequest::default()
        })
        .expect_err("over the cap");
        assert_eq!(err.field, "theme_css");

        assert!(validate_branding(&UpdateBrandingRequest {
            theme_css: "--skin-primary-500: #123456; --skin-accent-500: #654321;".into(),
            ..UpdateBrandingRequest::default()
        })
        .is_ok());
    }

    /// Clearing the favicon slot must take the derived icons with it: a derived
    /// PNG that outlived its source would be served as the brand forever.
    #[test]
    fn clearing_a_slot_covers_every_key_it_owns() {
        let favicon = BrandingAssetSlot::Favicon.storage_kinds();
        assert!(favicon.contains(&FAVICON_SOURCE_KIND));
        for derived in DERIVED_FAVICONS {
            assert!(
                favicon.contains(&derived.kind),
                "{} is derived from the source and must be cleared with it",
                derived.kind
            );
        }
        assert_eq!(BrandingAssetSlot::Mark.storage_kinds(), vec!["mark"]);
        assert_eq!(BrandingAssetSlot::Mascot.storage_kinds(), vec!["mascot"]);
    }

    /// The served-kind allow-list is what stops the path parameter naming an
    /// arbitrary row, so every key a slot writes has to be in it.
    #[test]
    fn every_stored_kind_is_servable_and_nothing_else_is() {
        for slot in [
            BrandingAssetSlot::Mark,
            BrandingAssetSlot::Favicon,
            BrandingAssetSlot::Mascot,
        ] {
            for kind in slot.storage_kinds() {
                assert!(is_servable_asset_kind(kind), "{kind} must be servable");
            }
        }
        for unknown in ["", "../mark", "favicon", "users", "mark-source"] {
            assert!(!is_servable_asset_kind(unknown), "{unknown} is not a key");
        }
    }
}
