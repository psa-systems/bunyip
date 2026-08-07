//! BUNYIP-145: the app's realtime event type + bus alias.
//!
//! DEV-528: the in-process bus and the SSE framing moved to the shared
//! `dunite-events` crate, generic over an event type. bunyip keeps its concrete
//! `BunyipEvent` enum (the wire shape the SPA consumes) and implements
//! `dunite_events::SseEvent` for it; `EventBus` is now a type alias for
//! `dunite_events::EventBus<BunyipEvent>`, so every `services::EventBus` path in
//! bunyip is unchanged.
//!
//! The bus fans a published event out to every connected tab of the affected
//! user (per-user channel) or to all users (a global event), and a long-lived
//! `GET /v1/events` SSE handler (`handlers::events`) streams it to the SPA,
//! which reacts without a hard refresh.

use dunite_events::SseEvent;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The in-process event bus for bunyip's realtime events. Registered once at
/// startup via `web::Data::new(Arc::new(EventBus::new()))`.
pub type EventBus = dunite_events::EventBus<BunyipEvent>;

/// Typed event published by mutation handlers. Wire shape on SSE is a JSON
/// object whose `type` field is the snake_case discriminant; the `event` SSE
/// field carries the same name so a strict consumer can route purely on
/// `event:` without parsing the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BunyipEvent {
    /// The user's JWT-feeding claims changed (role, lifetime_member,
    /// membership_status, etc.). SPA reaction: call /v1/auth/refresh, then
    /// /v1/auth/me, then update the in-memory CurrentUser signal.
    ClaimsChanged { user_id: Uuid },

    /// The user's optional profile fields (first_name / last_name / phone)
    /// changed. SPA reaction: refetch /v1/auth/me only; no token rotation
    /// needed since these fields gate nothing.
    ProfileChanged { user_id: Uuid },

    /// The application catalog changed (admin added / archived / renamed an
    /// application). Global event; fans out to every connected user. SPA
    /// reaction: refetch /v1/applications and re-render the launcher.
    ApplicationsChanged,

    /// The user's session is gone (admin revoked, log-out-all from another
    /// device, role-change revocation). SPA reaction: redirect to /login
    /// immediately. Includes a short reason string for the flash banner.
    SessionRevoked {
        user_id: Uuid,
        /// Short machine-readable reason: `admin_revoke`, `logout_all`,
        /// `role_change`, etc. Display-friendly text comes from the SPA.
        reason: &'static str,
    },

    /// The user deleted their own account (BUNYIP-211). Published AFTER the
    /// soft delete commits so local subscribers (audit log, SSE) observe the
    /// same terminal event that fans out to downstream apps via the webhook
    /// dispatch.
    AccountDeleted { user_id: Uuid },
}

impl SseEvent for BunyipEvent {
    /// The SSE `event:` field name, also used as the `type` discriminant.
    fn name(&self) -> &'static str {
        match self {
            BunyipEvent::ClaimsChanged { .. } => "claims_changed",
            BunyipEvent::ProfileChanged { .. } => "profile_changed",
            BunyipEvent::ApplicationsChanged => "applications_changed",
            BunyipEvent::SessionRevoked { .. } => "session_revoked",
            BunyipEvent::AccountDeleted { .. } => "account_deleted",
        }
    }

    /// The user this event targets, when applicable. Global events return
    /// `None` and the bus fans them out to every subscriber via the `global`
    /// channel instead of the per-user channel.
    fn target_user(&self) -> Option<Uuid> {
        match self {
            BunyipEvent::ClaimsChanged { user_id } => Some(*user_id),
            BunyipEvent::ProfileChanged { user_id } => Some(*user_id),
            BunyipEvent::ApplicationsChanged => None,
            BunyipEvent::SessionRevoked { user_id, .. } => Some(*user_id),
            BunyipEvent::AccountDeleted { user_id } => Some(*user_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_deleted_names_and_targets_the_user() {
        let uid = Uuid::new_v4();
        let ev = BunyipEvent::AccountDeleted { user_id: uid };
        assert_eq!(ev.name(), "account_deleted");
        assert_eq!(ev.target_user(), Some(uid));
    }

    #[test]
    fn global_event_targets_no_user() {
        assert_eq!(BunyipEvent::ApplicationsChanged.target_user(), None);
        assert_eq!(
            BunyipEvent::ApplicationsChanged.name(),
            "applications_changed"
        );
    }
}
