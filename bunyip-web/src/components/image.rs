//! `SafeImage` - thin `<img>` wrapper that swaps to a fallback when
//! the source 404s or is empty. Prevents the browser's default
//! broken-image glyph from leaking into the UI on user-supplied URLs
//! (avatars, OIDC client icons, etc.).

use dioxus::prelude::*;

/// Wrap any `<img>` you would otherwise render with a user-supplied
/// URL. Pass a fallback children slot (a letter, a SVG, whatever fits
/// the surrounding layout) - it shows when `src` is empty or when the
/// image element fires `onerror`.
///
/// The `<img>` still attempts the load when `src` is non-empty so the
/// network call appears in DevTools and the cached path is exercised;
/// the fallback only renders after a real failure.
#[component]
pub fn SafeImage(
    src: String,
    alt: String,
    /// Tailwind / CSS classes applied to the `<img>` element. The
    /// fallback should be styled by its own wrapper so layout is
    /// preserved either way.
    #[props(default = String::new())]
    class: String,
    /// Renders when `src` is empty/whitespace OR after the `<img>`
    /// emits an `onerror`. Use the same dimensions as the image so
    /// the layout doesn't shift.
    children: Element,
) -> Element {
    let mut errored = use_signal(|| false);
    let empty = src.trim().is_empty();

    if empty || errored() {
        rsx! { {children} }
    } else {
        rsx! {
            img {
                src: "{src}",
                alt: "{alt}",
                class: "{class}",
                // The browser fires `error` on a failed load (404, DNS,
                // CORS image without permissions, decode error, etc.).
                // We flip the signal to swap to the fallback.
                onerror: move |_| errored.set(true),
            }
        }
    }
}

/// Generic image-frame icon for places that don't have a domain-specific
/// fallback in mind. Sized to match the container; pass a Tailwind class
/// to override dimensions.
#[component]
pub fn ImagePlaceholderIcon(
    #[props(default = "w-6 h-6 text-bunyip-reed-500 dark:text-bunyip-reed-400")]
    class: &'static str,
) -> Element {
    rsx! {
        svg {
            class: "{class}",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "2",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            rect { x: "3", y: "5", width: "18", height: "14", rx: "2" }
            path { d: "M3 17l5-5 4 4 3-3 6 6" }
            circle { cx: "9", cy: "10", r: "1.5", fill: "currentColor" }
        }
    }
}
