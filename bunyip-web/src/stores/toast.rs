//! Lightweight toast notification store. Components call `push_toast(...)`
//! to add a message; `ToastViewport` renders the visible stack.

use dioxus::prelude::*;

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq)]
pub struct ToastStore(pub Signal<Vec<Toast>>);

pub fn use_toast_provider() -> ToastStore {
    use_context_provider(|| ToastStore(Signal::new(Vec::new())))
}

pub fn use_toast() -> ToastStore {
    use_context::<ToastStore>()
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl ToastStore {
    pub fn push(self, kind: ToastKind, message: impl Into<String>) {
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let toast = Toast {
            id,
            kind,
            message: message.into(),
        };
        let mut sig = self.0;
        sig.write().push(toast);
    }

    pub fn dismiss(self, id: u64) {
        let mut sig = self.0;
        sig.write().retain(|t| t.id != id);
    }

    pub fn success(self, message: impl Into<String>) {
        self.push(ToastKind::Success, message);
    }
    pub fn error(self, message: impl Into<String>) {
        self.push(ToastKind::Error, message);
    }
    pub fn info(self, message: impl Into<String>) {
        self.push(ToastKind::Info, message);
    }
}
