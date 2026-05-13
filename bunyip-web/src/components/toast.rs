use dioxus::prelude::*;

use crate::stores::toast::{use_toast, ToastKind};

#[component]
pub fn ToastViewport() -> Element {
    let store = use_toast();
    let toasts = store.0.read().clone();
    rsx! {
        div { class: "fixed top-4 right-4 z-[1000] flex flex-col gap-2 max-w-sm",
            for t in toasts.iter() {
                ToastItem { id: t.id, kind: t.kind, message: t.message.clone() }
            }
        }
    }
}

#[component]
fn ToastItem(id: u64, kind: ToastKind, message: String) -> Element {
    let store = use_toast();
    let id_for_close = id;

    let (bar_color, icon) = match kind {
        ToastKind::Success => ("bg-bunyip-reed-600", "✓"),
        ToastKind::Error => ("bg-red-500", "!"),
        ToastKind::Info => ("bg-bunyip-water-500", "i"),
    };

    rsx! {
        div { class: "flex items-stretch overflow-hidden rounded-lg border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 shadow-md",
            div { class: "w-1.5 {bar_color}" }
            div { class: "flex-1 px-4 py-3 flex items-start gap-3",
                span { class: "shrink-0 w-6 h-6 rounded-full {bar_color} text-white flex items-center justify-center text-sm font-bold",
                    "{icon}"
                }
                p { class: "flex-1 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "{message}"
                }
                button {
                    class: "shrink-0 text-bunyip-reed-500 hover:text-bunyip-reed-900",
                    onclick: move |_| { store.dismiss(id_for_close); },
                    "×"
                }
            }
        }
    }
}
