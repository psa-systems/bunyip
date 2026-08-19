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

pub mod common;
pub mod csrf;
pub mod ui;
