//! Client-IP forwarding for the BFF (BUNYIP-311). The module moved to the shared
//! `web-kit` crate (BUNYIP-589); re-exported here so `crate::client_ip::*` call
//! sites are unchanged. The middleware now takes the trusted-proxy CIDRs as
//! state; the wiring in `main.rs` passes `cfg.trusted_proxies`.

pub use web_kit::client_ip::*;
