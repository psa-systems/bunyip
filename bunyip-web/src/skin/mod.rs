//! BUNYIP-501: the per-app skin. Marketing, legal, docs, and the landing / 404
//! pages whose copy and assets are specific to this app (bunyip), kept separate
//! from the framework (layout scaffolding, ui, web-edge, and the auth /
//! dashboard / admin handlers) so a second app supplies its own skin without
//! forking the framework. The framework carries no marketing copy; this module
//! carries no generic app logic.
pub mod content;
pub mod public;
