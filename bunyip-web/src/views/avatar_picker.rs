//! Avatar picker (BUNYIP-408). The component moved to the shared `web-kit` crate
//! (BUNYIP-589); here bunyip-web adapts it to its own `User` and routes.
//!
//! `web-kit`'s picker is consumer-agnostic: it takes the upload / remove
//! endpoints as arguments and reads the image src / letter fallback through the
//! `web_kit::avatar::Avatar` trait. This wrapper implements that trait for
//! bunyip-web's `User` and pins the `/settings/avatar` routes, so the existing
//! `avatar_picker::avatar_picker(&user)` call site is unchanged.

use maud::Markup;

use crate::api::types::User;

pub use web_kit::avatar::{Avatar, AVATAR_PICKER_CSS, AVATAR_SLOT_CSS};

impl Avatar for User {
    // The inherent `User` methods win method resolution over these same-named
    // trait methods, so `self.avatar_*()` calls the inherent ones, not itself.
    fn avatar_src(&self) -> Option<String> {
        self.avatar_src()
    }
    fn avatar_initial(&self) -> String {
        self.avatar_initial()
    }
}

/// Render the avatar picker for bunyip-web's `User`, wired to the `/settings`
/// avatar routes.
pub fn avatar_picker(user: &User) -> Markup {
    web_kit::avatar::avatar_picker(user, "/settings/avatar", "/settings/avatar/remove")
}

#[cfg(test)]
mod tests {
    /// BUNYIP-554: the picker's stylesheet and controller no longer ship in the
    /// shared head, so a page that renders `avatar_picker` through the plain
    /// `dashboard_response` gets an unstyled, inert component. Every handler
    /// file that renders it must also reach for the picker-carrying response.
    #[test]
    fn every_handler_that_renders_the_picker_asks_for_its_assets() {
        let handlers = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut stack = vec![handlers];
        let (mut renderers, mut offenders) = (0, Vec::new());
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable handler dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("readable source file");
                if !body.contains("avatar_picker::avatar_picker(") {
                    continue;
                }
                renderers += 1;
                if !body.contains("dashboard_response_with_avatar_picker(") {
                    offenders.push(path.display().to_string());
                }
            }
        }
        assert_eq!(
            renderers, 1,
            "expected exactly one page to render the picker"
        );
        assert!(
            offenders.is_empty(),
            "these render the avatar picker without shipping its CSS / JS: {offenders:?}"
        );
    }
}
