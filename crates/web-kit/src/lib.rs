//! Branding-free shared SSR web-kit (BUNYIP-502).
//!
//! Generic Maud + axum building blocks lifted out of bunyip-web so a second
//! Axum + Maud + htmx front-end (menkent web) can consume the same UI toolkit
//! instead of copying it. Nothing here references a product name, the branding
//! record, app-specific routes, or api types: the consumer passes those in.
//!
//! bunyip-web depends on it by path (`web-kit = { path = "../crates/web-kit" }`)
//! and re-exports each module, so existing `crate::views::ui` / `crate::csrf`
//! call sites are unchanged. menkent web consumes it the same way once its web
//! enters focus: a path dependency in a shared checkout, or a git dependency on
//! this repository.

// Two pieces of bunyip-web's SSR surface deliberately did NOT move here
// (BUNYIP-589):
//
// - `security.rs` (the CSP layer). Its policy hardcodes bunyip's own integration
//   hosts (checkout.stripe.com, billing.stripe.com, api.pwnedpasswords.com),
//   which are app-specific, not generic. The only generic part - setting a CSP
//   response header - is already `tower_http::SetResponseHeaderLayer`, so a
//   shared wrapper would be indirection without payoff. A second app supplies its
//   own policy and applies it with the same off-the-shelf layer.
// - The JS behaviours (`app.js` / `password.js` / `theme.js`). They are served
//   from the consumer's `/assets` directory by a `ServeDir`, not embedded via
//   `include_str!`, so a crate cannot own them without a build-time copy. They
//   are already brand-free and guarded, so they stay beside the consumer's other
//   static assets.

pub mod avatar;
pub mod client_ip;
pub mod common;
pub mod csrf;
pub mod shell;
pub mod ui;
