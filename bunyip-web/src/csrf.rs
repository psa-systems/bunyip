//! CSRF Origin/Referer defense (BUNYIP-259). The middleware moved to the shared
//! `web-kit` crate (BUNYIP-502); re-exported here so `crate::csrf::*` call sites
//! are unchanged. The full rationale lives in `web-kit/src/csrf.rs`.

// SPEC-11.11.1, SPEC-11.11.2: behavior lives in web-kit.
pub use web_kit::csrf::*;
