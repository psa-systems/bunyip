//! BUNYIP-560/BUNYIP-744: derive every brand asset slot from one uploaded
//! source image.
//!
//! The admin uploads ONE image per slot; the sized variant(s) the layout
//! actually renders are produced here and written in the same transaction, so
//! a deployment never carries a half-replaced set. The favicon slot derives
//! seven icons (five PNG sizes, `apple-touch-icon`, `favicon.ico`); the mark
//! slot derives the one 64px nav variant; the mascot slot derives the 448/896
//! pair the landing page's hero `srcset` uses.
//!
//! Decoding and resizing are CPU work measured in hundreds of milliseconds for a
//! large source, so the caller runs [`derive_favicons`] / [`derive_mark`] /
//! [`derive_mascot`] on the blocking pool for the same reason password hashing
//! moved off the arbiters (BUNYIP-553): actix never migrates a connection's
//! futures to another worker, so a slow synchronous step on the request future
//! stalls every other request on that arbiter.

use bunyip_domain::models::{
    DERIVED_FAVICONS, DERIVED_MASCOTS, FAVICON_SOURCE_KIND, MARK_DERIVED_SIZE, MARK_SOURCE_KIND,
    MASCOT_SOURCE_KIND,
};
use image::imageops::FilterType;
use image::{ExtendedColorType, ImageEncoder};

/// One row to store: the key, its MIME type, and the bytes.
pub type DerivedAsset = (&'static str, String, Vec<u8>);

/// Encode an RGBA buffer as PNG, at the strongest compression the encoder
/// offers: derived images are produced once at upload time and read many
/// times, so the extra encode cost is worth it for the smaller file every
/// later request serves.
fn encode_png(rgba: &image::RgbaImage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    image::codecs::png::PngEncoder::new_with_quality(
        &mut buf,
        image::codecs::png::CompressionType::Best,
        image::codecs::png::FilterType::Adaptive,
    )
    .write_image(
        rgba.as_raw(),
        rgba.width(),
        rgba.height(),
        ExtendedColorType::Rgba8,
    )
    .map_err(|e| format!("Could not encode the {}px icon: {e}", rgba.width()))?;
    Ok(buf)
}

/// Encode an RGBA buffer as a single-frame ICO. ICO frames are capped at 256px
/// by the format; the set only ever asks for 48.
fn encode_ico(rgba: &image::RgbaImage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    image::codecs::ico::IcoEncoder::new(&mut buf)
        .write_image(
            rgba.as_raw(),
            rgba.width(),
            rgba.height(),
            ExtendedColorType::Rgba8,
        )
        .map_err(|e| format!("Could not encode favicon.ico: {e}"))?;
    Ok(buf)
}

/// Derive the whole favicon set from `source`, plus the source itself.
///
/// Returns the complete new content of the favicon slot, so the caller writes it
/// as one unit. Every error is a message the admin form renders: this runs on an
/// admin upload, and "the file could not be decoded" has to reach the person who
/// chose the file, not just the log.
///
/// Each icon is `resize_to_fill`ed, so a non-square source is centre-cropped
/// rather than squashed: a favicon that keeps its aspect ratio and loses its
/// edges reads as the brand; a stretched one does not.
pub fn derive_favicons(source: Vec<u8>) -> Result<Vec<DerivedAsset>, String> {
    let mime = image::guess_format(&source)
        .map_err(|_| "Could not read that file as an image.".to_string())?;
    let decoded = image::load_from_memory_with_format(&source, mime)
        .map_err(|e| format!("Could not read that image: {e}"))?;

    let mut assets: Vec<DerivedAsset> = Vec::with_capacity(DERIVED_FAVICONS.len() + 1);
    for derived in DERIVED_FAVICONS {
        let resized = decoded
            .resize_to_fill(derived.size, derived.size, FilterType::Lanczos3)
            .to_rgba8();
        let bytes = if derived.mime == "image/x-icon" {
            encode_ico(&resized)?
        } else {
            encode_png(&resized)?
        };
        assets.push((derived.kind, derived.mime.to_string(), bytes));
    }

    // Keep exactly what was uploaded, so a later change to the derived set can
    // re-derive without asking the admin to find the original file again.
    let source_mime = mime.to_mime_type().to_string();
    assets.push((FAVICON_SOURCE_KIND, source_mime, source));
    Ok(assets)
}

/// BUNYIP-744: derive the one nav-mark variant `views::layout::brand_mark`
/// renders (28 CSS pixels, 2x headroom) from the uploaded source, keeping the
/// source row exactly as the favicon slot does.
///
/// `resize`, not `resize_to_fill`: the mark is rendered with `object-contain`
/// today (a non-square upload is letterboxed, not cropped), and a derived
/// variant must not change that.
pub fn derive_mark(source: Vec<u8>) -> Result<Vec<DerivedAsset>, String> {
    let mime = image::guess_format(&source)
        .map_err(|_| "Could not read that file as an image.".to_string())?;
    let decoded = image::load_from_memory_with_format(&source, mime)
        .map_err(|e| format!("Could not read that image: {e}"))?;

    let resized = decoded
        .resize(MARK_DERIVED_SIZE, MARK_DERIVED_SIZE, FilterType::Lanczos3)
        .to_rgba8();
    let bytes = encode_png(&resized)?;

    let source_mime = mime.to_mime_type().to_string();
    Ok(vec![
        ("mark", "image/png".to_string(), bytes),
        (MARK_SOURCE_KIND, source_mime, source),
    ])
}

/// BUNYIP-744: derive the two sizes the landing page hero's `srcset` uses
/// (448 and 896 on the long edge) from the uploaded source, keeping the source
/// row exactly as the favicon slot does.
///
/// `resize`, not `resize_to_fill`: the hero is an illustration, and cropping
/// it to fill a square would cut off part of the artwork.
pub fn derive_mascot(source: Vec<u8>) -> Result<Vec<DerivedAsset>, String> {
    let mime = image::guess_format(&source)
        .map_err(|_| "Could not read that file as an image.".to_string())?;
    let decoded = image::load_from_memory_with_format(&source, mime)
        .map_err(|e| format!("Could not read that image: {e}"))?;

    let mut assets: Vec<DerivedAsset> = Vec::with_capacity(DERIVED_MASCOTS.len() + 1);
    for derived in DERIVED_MASCOTS {
        let resized = decoded
            .resize(derived.size, derived.size, FilterType::Lanczos3)
            .to_rgba8();
        assets.push((derived.kind, "image/png".to_string(), encode_png(&resized)?));
    }

    let source_mime = mime.to_mime_type().to_string();
    assets.push((MASCOT_SOURCE_KIND, source_mime, source));
    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64x40 PNG: deliberately non-square, so the crop path is what runs.
    fn source_png() -> Vec<u8> {
        let mut img = image::RgbaImage::new(64, 40);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            *pixel = image::Rgba([(x * 4) as u8, (y * 6) as u8, 128, 255]);
        }
        let mut buf = Vec::new();
        image::codecs::png::PngEncoder::new(&mut buf)
            .write_image(img.as_raw(), 64, 40, ExtendedColorType::Rgba8)
            .expect("encode the fixture");
        buf
    }

    /// One upload produces the whole set the document head references, each at
    /// the exact declared size and square. A missing or mis-sized member here
    /// is a browser falling back to a blurred icon or to nothing.
    #[test]
    fn one_source_yields_every_icon_the_head_references() {
        let assets = derive_favicons(source_png()).expect("derivation succeeds");
        assert_eq!(assets.len(), DERIVED_FAVICONS.len() + 1);

        for derived in DERIVED_FAVICONS {
            let (_, mime, bytes) = assets
                .iter()
                .find(|(kind, _, _)| *kind == derived.kind)
                .unwrap_or_else(|| panic!("{} was not derived", derived.kind));
            assert_eq!(mime, derived.mime);
            let decoded = image::load_from_memory(bytes)
                .unwrap_or_else(|e| panic!("{} is not a readable image: {e}", derived.kind));
            assert_eq!(
                (decoded.width(), decoded.height()),
                (derived.size, derived.size),
                "{} must be square at its declared size",
                derived.kind
            );
        }

        let (_, _, stored) = assets
            .iter()
            .find(|(kind, _, _)| *kind == FAVICON_SOURCE_KIND)
            .expect("the source is kept");
        assert_eq!(stored, &source_png(), "the source is stored byte-for-byte");
    }

    /// A file that is not an image fails with a message the admin form renders,
    /// and produces nothing: the caller writes the whole set or none of it.
    #[test]
    fn a_non_image_fails_with_a_renderable_reason() {
        let err = derive_favicons(b"this is not an image".to_vec())
            .expect_err("a text file is not an icon source");
        assert!(!err.is_empty());
        assert!(err.contains("image"), "{err}");
    }

    /// A large non-square source, standing in for the "4096px, 1.9 MiB PNG
    /// mascot" the issue names.
    fn large_source_png(width: u32, height: u32) -> Vec<u8> {
        let mut img = image::RgbaImage::new(width, height);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            *pixel = image::Rgba([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255]);
        }
        let mut buf = Vec::new();
        image::codecs::png::PngEncoder::new(&mut buf)
            .write_image(img.as_raw(), width, height, ExtendedColorType::Rgba8)
            .expect("encode the fixture");
        buf
    }

    /// BUNYIP-744: the mark derives to exactly one 64px variant, plus the kept
    /// source. `resize`, not `resize_to_fill`, so a non-square upload is not
    /// cropped: its long edge lands on the target size and the short edge
    /// follows the aspect ratio.
    #[test]
    fn a_mark_upload_derives_one_64px_variant_and_keeps_the_source() {
        let source = source_png(); // 64x40
        let assets = derive_mark(source.clone()).expect("derivation succeeds");
        assert_eq!(assets.len(), 2);

        let (_, mime, bytes) = assets
            .iter()
            .find(|(kind, _, _)| *kind == "mark")
            .expect("the derived mark is present");
        assert_eq!(mime, "image/png");
        let decoded = image::load_from_memory(bytes).expect("the derived mark decodes");
        assert_eq!(decoded.width(), MARK_DERIVED_SIZE, "the long edge is 64px");
        assert!(
            decoded.height() < MARK_DERIVED_SIZE,
            "a non-square source is not cropped to a square"
        );

        let (_, _, stored) = assets
            .iter()
            .find(|(kind, _, _)| *kind == MARK_SOURCE_KIND)
            .expect("the source is kept");
        assert_eq!(stored, &source, "the source is stored byte-for-byte");
    }

    /// A file that is not an image fails with a renderable reason and produces
    /// nothing, matching the favicon slot's guarantee that a failed derivation
    /// never partially writes.
    #[test]
    fn a_non_image_mark_upload_fails_with_a_renderable_reason() {
        let err = derive_mark(b"this is not an image".to_vec()).expect_err("not an image");
        assert!(err.contains("image"), "{err}");
    }

    /// BUNYIP-744 acceptance criterion: a 4096px mascot upload produces a 448px
    /// derived variant, the one the 448px viewport's `srcset` entry selects,
    /// under 150,000 bytes.
    #[test]
    fn a_4096px_mascot_upload_derives_a_448px_variant_under_150kb() {
        let source = large_source_png(4096, 4096);
        assert!(
            source.len() > 1_000_000,
            "the fixture should be a large source, was {} bytes",
            source.len()
        );

        let assets = derive_mascot(source.clone()).expect("derivation succeeds");
        assert_eq!(assets.len(), DERIVED_MASCOTS.len() + 1);

        for derived in DERIVED_MASCOTS {
            let (_, mime, bytes) = assets
                .iter()
                .find(|(kind, _, _)| *kind == derived.kind)
                .unwrap_or_else(|| panic!("{} was not derived", derived.kind));
            assert_eq!(mime, "image/png");
            let decoded = image::load_from_memory(bytes)
                .unwrap_or_else(|e| panic!("{} is not a readable image: {e}", derived.kind));
            assert_eq!(
                decoded.width().max(decoded.height()),
                derived.size,
                "{}'s long edge must be {}",
                derived.kind,
                derived.size
            );
        }

        let (_, _, mascot_448) = assets
            .iter()
            .find(|(kind, _, _)| *kind == "mascot")
            .expect("the 448px variant is present");
        assert!(
            mascot_448.len() < 150_000,
            "the 448px variant a 448px viewport selects must be under 150,000 bytes, was {}",
            mascot_448.len()
        );

        let (_, _, stored) = assets
            .iter()
            .find(|(kind, _, _)| *kind == MASCOT_SOURCE_KIND)
            .expect("the source is kept");
        assert_eq!(stored, &source, "the source is stored byte-for-byte");
    }

    /// A non-square illustration is not cropped: the short edge follows the
    /// aspect ratio rather than being forced to the target square.
    #[test]
    fn a_non_square_mascot_is_not_cropped() {
        let source = large_source_png(4096, 2048);
        let assets = derive_mascot(source).expect("derivation succeeds");
        let (_, _, bytes) = assets
            .iter()
            .find(|(kind, _, _)| *kind == "mascot")
            .expect("the 448px variant is present");
        let decoded = image::load_from_memory(bytes).expect("decodes");
        assert_eq!(decoded.width(), 448, "the long edge lands on the target");
        assert_eq!(decoded.height(), 224, "the short edge follows the ratio");
    }

    #[test]
    fn a_non_image_mascot_upload_fails_with_a_renderable_reason() {
        let err = derive_mascot(b"this is not an image".to_vec()).expect_err("not an image");
        assert!(err.contains("image"), "{err}");
    }
}
