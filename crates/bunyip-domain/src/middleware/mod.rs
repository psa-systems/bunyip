//! Middleware: Bunyip's domain extractors (auth) and auto-ban, plus the generic
//! kernel middleware (request-id, security-headers) re-exported from dunite-core
//! so `crate::middleware::request_id::*` / `::security_headers::*` paths resolve.

pub mod auth;
pub mod auto_ban;

// Generic kernel middleware.
pub use dunite_core::middleware::{request_id, security_headers};
pub use dunite_core::middleware::{CspConfig, RequestIdMiddleware, SecurityHeaders};

// Domain extractors / middleware.
pub use auth::{
    extract_client_ip, extract_device_info, request_user, resolve_rate_limit_subject,
    super_admin_allowed, verify_once, AdminUser, AuthCookies, AuthenticatedUser, MemberUser,
    OptionalUser, SuperAdminUser, VerifiedIdentity,
};
pub use auto_ban::{AutoBanMiddleware, AutoBanService, BanInfo};
