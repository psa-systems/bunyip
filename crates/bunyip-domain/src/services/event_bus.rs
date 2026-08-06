//! BUNYIP-145: in-process event bus.
//!
//! The bus is the server-side half of bunyip-web's "no hard refresh anywhere"
//! UX. When an admin grants lifetime to a user, when the user edits their
//! profile, when a Stripe webhook flips membership_status - any mutation
//! that affects the user's open SPA tab - the mutation handler `publish()`s
//! a typed event. A long-lived `GET /v1/events` Server-Sent Events handler
//! reads from this bus, fans the event out to every connected tab of the
//! affected user (or all users for global events), and the SPA reacts
//! transparently.
//!
//! See `BUNYIP-145` for the full design, and `BUNYIP-144` for the security
//! companion (refresh-token revocation on the same mutation set).
//!
//! ## Topology
//!
//! One [`tokio::sync::broadcast`] channel per `user_id`, allocated on first
//! subscribe. Capacity is bounded (`BROADCAST_CAPACITY`) so a slow consumer
//! cannot grow the buffer unbounded; SSE clients that fall behind get a
//! `Lagged(n)` signal and the handler emits a `resync` event so the SPA
//! refetches state from scratch.
//!
//! Global events (e.g. `applications_changed`) fan out via a single
//! always-allocated `global` channel that every SSE handler also subscribes
//! to.
//!
//! Channels are reaped lazily: a channel with no live receivers stays in
//! the map until the next `publish_user` call for that user finds zero
//! subscribers, at which point it is removed. This avoids per-disconnect
//! map churn and keeps the lock granularity coarse.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Per-user channel capacity. 100 events is far above any realistic burst
/// (a Stripe webhook flip + an admin grant + a profile edit is three) but
/// gives a slow consumer a wide window before lagging.
const BROADCAST_CAPACITY: usize = 100;

/// Typed event published by mutation handlers. Wire shape on SSE is a JSON
/// object whose `type` field is the snake_case discriminant; the `event`
/// SSE field carries the same name so a strict consumer can route purely on
/// `event:` without parsing the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BunyipEvent {
    /// The user's JWT-feeding claims changed (role, lifetime_member,
    /// membership_status, etc.). SPA reaction: call /v1/auth/refresh, then
    /// /v1/auth/me, then update the in-memory CurrentUser signal. The
    /// downstream page render reads CurrentUser, so per-app gates
    /// (dashboard tile state) re-evaluate without a hard refresh.
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
    /// immediately. Includes a short reason string the SPA can use for the
    /// flash banner after re-login.
    SessionRevoked {
        user_id: Uuid,
        /// Short machine-readable reason: `admin_revoke`, `logout_all`,
        /// `role_change`, etc. Display-friendly text comes from the SPA.
        reason: &'static str,
    },

    /// The user deleted their own account (BUNYIP-211). Published AFTER the
    /// soft delete commits so local subscribers (audit log, SSE) observe the
    /// same terminal event that fans out to downstream apps via the webhook
    /// dispatch. Targets the deleted user; their open tabs already redirect to
    /// /login on the accompanying `SessionRevoked`, but the typed event lets
    /// any in-process listener react to the delete specifically.
    AccountDeleted { user_id: Uuid },
}

impl BunyipEvent {
    /// The SSE `event:` field name, also used as the `type` discriminant.
    pub fn name(&self) -> &'static str {
        match self {
            BunyipEvent::ClaimsChanged { .. } => "claims_changed",
            BunyipEvent::ProfileChanged { .. } => "profile_changed",
            BunyipEvent::ApplicationsChanged => "applications_changed",
            BunyipEvent::SessionRevoked { .. } => "session_revoked",
            BunyipEvent::AccountDeleted { .. } => "account_deleted",
        }
    }

    /// The user this event targets, when applicable. Global events return
    /// `None` and the SSE handler fans them out to every subscriber via the
    /// `global` channel instead of the per-user channel.
    pub fn target_user(&self) -> Option<Uuid> {
        match self {
            BunyipEvent::ClaimsChanged { user_id } => Some(*user_id),
            BunyipEvent::ProfileChanged { user_id } => Some(*user_id),
            BunyipEvent::ApplicationsChanged => None,
            BunyipEvent::SessionRevoked { user_id, .. } => Some(*user_id),
            BunyipEvent::AccountDeleted { user_id } => Some(*user_id),
        }
    }
}

/// The in-process event bus. Cheap to clone (Arc'd internals). Registered
/// once at startup via `web::Data::new(Arc::new(EventBus::new()))`.
#[derive(Clone)]
pub struct EventBus {
    /// Per-user channels. Keyed by `user_id`. Allocated on first subscribe;
    /// reaped when `publish_user` finds zero subscribers (see module docs).
    per_user: Arc<Mutex<HashMap<Uuid, broadcast::Sender<BunyipEvent>>>>,
    /// Always-allocated channel for global events. Every SSE handler
    /// subscribes alongside the per-user channel.
    global: broadcast::Sender<BunyipEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (global, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            per_user: Arc::new(Mutex::new(HashMap::new())),
            global,
        }
    }

    /// Subscribe a connecting SSE client to its user's per-user channel.
    /// Returns a receiver that yields every subsequent `publish_user` for
    /// the same user. Closing the receiver frees the slot lazily.
    pub fn subscribe_user(&self, user_id: Uuid) -> broadcast::Receiver<BunyipEvent> {
        let mut map = self.per_user.lock().expect("event-bus map poisoned");
        let sender = map.entry(user_id).or_insert_with(|| {
            let (s, _) = broadcast::channel(BROADCAST_CAPACITY);
            s
        });
        sender.subscribe()
    }

    /// Subscribe a connecting SSE client to global events. Every handler
    /// calls this in addition to `subscribe_user`.
    pub fn subscribe_global(&self) -> broadcast::Receiver<BunyipEvent> {
        self.global.subscribe()
    }

    /// Publish an event. Routes to the per-user channel when the event
    /// targets a specific user (`claims_changed`, `profile_changed`,
    /// `session_revoked`), and to the global channel otherwise
    /// (`applications_changed`).
    ///
    /// Always returns `Ok` - a publish to a channel with no live
    /// subscribers is a normal idle case, not an error. Errors from
    /// `broadcast::Sender::send` (`SendError`) only fire when the channel
    /// is closed, which cannot happen with our `Arc`'d senders.
    pub fn publish(&self, event: BunyipEvent) {
        match event.target_user() {
            Some(user_id) => self.publish_user(user_id, event),
            None => {
                let _ = self.global.send(event);
            }
        }
    }

    fn publish_user(&self, user_id: Uuid, event: BunyipEvent) {
        let mut map = self.per_user.lock().expect("event-bus map poisoned");
        let Some(sender) = map.get(&user_id) else {
            // No tabs open for this user: drop the event. The user will see
            // the new state on their next sign-in via the live DB row.
            return;
        };
        match sender.send(event) {
            Ok(_n) => { /* delivered to N receivers */ }
            Err(_send_err) => {
                // All receivers dropped between get() and send(): reap the
                // channel so the next subscribe_user starts fresh.
                map.remove(&user_id);
            }
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn per_user_publish_reaches_subscriber() {
        let bus = EventBus::new();
        let uid = Uuid::new_v4();
        let mut rx = bus.subscribe_user(uid);
        bus.publish(BunyipEvent::ClaimsChanged { user_id: uid });
        let ev = rx.recv().await.expect("recv");
        assert_eq!(ev.name(), "claims_changed");
    }

    #[tokio::test]
    async fn publish_to_other_user_does_not_reach() {
        let bus = EventBus::new();
        let mut a = bus.subscribe_user(Uuid::new_v4());
        let other = Uuid::new_v4();
        bus.publish(BunyipEvent::ClaimsChanged { user_id: other });
        // Receiver should remain empty; try_recv yields Empty.
        assert!(matches!(
            a.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn global_publish_reaches_every_subscriber() {
        let bus = EventBus::new();
        let mut a = bus.subscribe_global();
        let mut b = bus.subscribe_global();
        bus.publish(BunyipEvent::ApplicationsChanged);
        assert_eq!(a.recv().await.unwrap().name(), "applications_changed");
        assert_eq!(b.recv().await.unwrap().name(), "applications_changed");
    }

    #[tokio::test]
    async fn no_subscribers_is_a_noop() {
        let bus = EventBus::new();
        bus.publish(BunyipEvent::ClaimsChanged {
            user_id: Uuid::new_v4(),
        });
        // No panic, no error path observable. The publish path drops the
        // event silently when the per-user channel has no receivers.
    }

    #[test]
    fn account_deleted_names_and_targets_the_user() {
        let uid = Uuid::new_v4();
        let ev = BunyipEvent::AccountDeleted { user_id: uid };
        assert_eq!(ev.name(), "account_deleted");
        assert_eq!(ev.target_user(), Some(uid));
    }

    #[tokio::test]
    async fn session_revoked_carries_reason() {
        let bus = EventBus::new();
        let uid = Uuid::new_v4();
        let mut rx = bus.subscribe_user(uid);
        bus.publish(BunyipEvent::SessionRevoked {
            user_id: uid,
            reason: "admin_revoke",
        });
        match rx.recv().await.unwrap() {
            BunyipEvent::SessionRevoked { reason, .. } => assert_eq!(reason, "admin_revoke"),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
