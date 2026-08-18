//! BUNYIP-560: derive the favicon set from one uploaded source image.
//!
//! The admin uploads ONE image; every icon the document head references (five
//! PNG sizes, `apple-touch-icon`, `favicon.ico`) is produced here and written in
//! the same transaction, so a deployment never carries a half-replaced icon set
//! and the operator never hand-cuts seven files.
//!
//! Decoding and resizing are CPU work measured in hundreds of milliseconds for a
//! large source, so the caller runs [`derive_favicons`] on the blocking pool for
//! the same reason password hashing moved off the arbiters (BUNYIP-553): actix
//! never migrates a connection's futures to another worker, so a slow synchronous
//! step on the request future stalls every other request on that arbiter.

use bunyip_domain::models::{DERIVED_FAVICONS, FAVICON_SOURCE_KIND};
use image::imageops::FilterType;
use image::{ExtendedColorType, ImageEncoder};

/// One row to store: the key, its MIME type, and the bytes.
pub type DerivedAsset = (&'static str, String, Vec<u8>);

/// Encode an RGBA buffer as PNG.
fn encode_png(rgba: &image::RgbaImage) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    image::codecs::png::PngEncoder::new(&mut buf)
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
}
