//! In-memory, router-style error log (BUNYIP-327).
//!
//! Production auth/rate-limit problems on NC01 were only visible over SSH. This
//! captures every ERROR-level `tracing` event into a bounded ring buffer that
//! an admin-gated web view (`GET /v1/admin/logs`) renders, filterable by
//! category, so the team can diagnose recurring issues in-product.
//!
//! Design (see the issue): the buffer is intentionally in-memory and rotated
//! (oldest evicted at capacity), like a router's log ring - no migration, no
//! persistence. Entries are lost on restart/redeploy; that is an accepted
//! trade-off for v1. Only ERROR is captured; warnings are excluded by
//! construction so the view stays actionable. Rate-limit trips are emitted at
//! ERROR with `category = "rate_limit"` and a `client` field precisely so they
//! surface here and stay attributable (see `handlers::check_rate_limit` and the
//! email-resend limits in `bunyip_domain::services::auth`).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Number of ERROR events retained before the oldest is evicted. Ample for
/// live diagnosis without letting the buffer grow unbounded.
pub const DEFAULT_CAPACITY: usize = 1000;

/// A single captured ERROR event. The three fields the view keys on - the
/// error category, the affected route, and the client it is attributable to -
/// are pulled out of the structured tracing fields; anything else lands in
/// `fields` so no context is dropped.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorLogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    /// Emitting module path (`tracing` target), e.g. `bunyip_api::handlers`.
    pub target: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Remaining structured fields (name -> rendered value), so an entry keeps
    /// whatever diagnostic context the call site attached.
    pub fields: BTreeMap<String, String>,
}

/// Thread-safe bounded ring buffer of [`ErrorLogEntry`]. Cheap to clone (shared
/// `Arc`), so the same buffer is handed to both the capture layer and the admin
/// handler.
#[derive(Clone)]
pub struct ErrorLogBuffer {
    inner: Arc<Mutex<VecDeque<ErrorLogEntry>>>,
    capacity: usize,
}

impl ErrorLogBuffer {
    /// Create a buffer holding at most `capacity` entries (clamped to >= 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity.min(1024)))),
            capacity,
        }
    }

    /// Append an entry, evicting the oldest when full. A poisoned lock is
    /// recovered rather than propagated: a logging buffer must never panic the
    /// request that emitted the event.
    pub fn push(&self, entry: ErrorLogEntry) {
        let mut buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() == self.capacity {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Newest-first snapshot, optionally filtered to a single `category`
    /// (exact match). Clones out so the lock is released immediately.
    pub fn snapshot(&self, category: Option<&str>) -> Vec<ErrorLogEntry> {
        let buf = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        buf.iter()
            .rev()
            .filter(|e| category.is_none_or(|c| e.category.as_deref() == Some(c)))
            .cloned()
            .collect()
    }

    /// Current number of retained entries.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum entries the buffer retains before rotation.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// A `tracing` layer that copies ERROR-level events into an [`ErrorLogBuffer`].
/// Slots into the existing subscriber registry alongside the fmt layer, so no
/// call site changes are needed for an error to appear in the view - any
/// `tracing::error!` is captured with its structured fields intact.
pub struct ErrorLogLayer {
    buffer: ErrorLogBuffer,
}

impl ErrorLogLayer {
    pub fn new(buffer: ErrorLogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for ErrorLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // Errors only: warnings are excluded from the buffer by construction.
        if *meta.level() != Level::ERROR {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.buffer.push(ErrorLogEntry {
            timestamp: Utc::now(),
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: visitor.message.unwrap_or_default(),
            category: visitor.category,
            route: visitor.route,
            client: visitor.client,
            fields: visitor.fields,
        });
    }
}

/// Collects an event's structured fields, splitting the three the view keys on
/// (`category` / `route` / `client`) and the log `message` out of the generic
/// bag.
#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    category: Option<String>,
    route: Option<String>,
    client: Option<String>,
    fields: BTreeMap<String, String>,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: String) {
        match field.name() {
            "message" => self.message = Some(value),
            "category" => self.category = Some(value),
            "route" => self.route = Some(value),
            "client" => self.client = Some(value),
            other => {
                self.fields.insert(other.to_string(), value);
            }
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_string());
    }

    // Everything non-string (ints, bools, `%display`, `?debug`, the message
    // itself) funnels through the default `Visit` impls into `record_debug`.
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    fn subscriber(buffer: ErrorLogBuffer) -> impl Subscriber {
        Registry::default().with(ErrorLogLayer::new(buffer))
    }

    #[test]
    fn captures_error_but_not_warning() {
        let buf = ErrorLogBuffer::new(16);
        with_default(subscriber(buf.clone()), || {
            tracing::warn!(category = "rate_limit", "a warning must never be captured");
            tracing::error!(
                category = "rate_limit",
                client = "1.2.3.4",
                route = "/v1/auth/login",
                "rate limit exceeded"
            );
        });
        let entries = buf.snapshot(None);
        assert_eq!(entries.len(), 1, "only the ERROR event is captured");
        let e = &entries[0];
        assert_eq!(e.message, "rate limit exceeded");
        assert_eq!(e.category.as_deref(), Some("rate_limit"));
        assert_eq!(e.client.as_deref(), Some("1.2.3.4"));
        assert_eq!(e.route.as_deref(), Some("/v1/auth/login"));
    }

    #[test]
    fn category_filter_selects_matching_entries() {
        let buf = ErrorLogBuffer::new(16);
        with_default(subscriber(buf.clone()), || {
            tracing::error!(category = "rate_limit", "one");
            tracing::error!(category = "auth", "two");
            tracing::error!("three"); // no category
        });
        assert_eq!(buf.snapshot(Some("rate_limit")).len(), 1);
        assert_eq!(buf.snapshot(Some("auth")).len(), 1);
        assert_eq!(buf.snapshot(None).len(), 3);
    }

    #[test]
    fn ring_rotates_oldest_out_at_capacity() {
        let buf = ErrorLogBuffer::new(2);
        with_default(subscriber(buf.clone()), || {
            tracing::error!("one");
            tracing::error!("two");
            tracing::error!("three");
        });
        let entries = buf.snapshot(None); // newest-first
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "three");
        assert_eq!(entries[1].message, "two");
        assert_eq!(buf.capacity(), 2);
    }

    #[test]
    fn extra_fields_are_retained() {
        let buf = ErrorLogBuffer::new(4);
        with_default(subscriber(buf.clone()), || {
            tracing::error!(
                category = "rate_limit",
                action = "login",
                retry_after = 42,
                "hit"
            );
        });
        let e = &buf.snapshot(None)[0];
        assert_eq!(e.fields.get("action").map(String::as_str), Some("login"));
        assert_eq!(e.fields.get("retry_after").map(String::as_str), Some("42"));
    }
}
