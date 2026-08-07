//! In-memory, router-style error log (BUNYIP-327).
//!
//! DEV-529: the implementation moved to `dunite_core::error_log`, shared with
//! a8n-tools. This module is kept as the seam so every `crate::error_log::*`
//! path in bunyip is unchanged (`ErrorLogBuffer`, `ErrorLogLayer`,
//! `ErrorLogEntry`, `DEFAULT_CAPACITY`).
//!
//! Behaviour is identical: a bounded in-memory ring captures ERROR-level
//! tracing events (only ERROR; warnings excluded by construction), with the
//! category / route / client fields pulled out of the structured tracing
//! fields for the admin log view. Entries are lost on restart (accepted).

pub use dunite_core::error_log::{ErrorLogBuffer, ErrorLogEntry, ErrorLogLayer, DEFAULT_CAPACITY};
