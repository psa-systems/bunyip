//! Friendly error card. Replaces raw `Request failed (404)` red
//! banners on surfaces whose backend isn't wired yet, plus the
//! generic "retry" affordance on transient failures.

use dioxus::prelude::*;

#[derive(Clone, PartialEq)]
pub enum ErrorVariant {
    /// 404 from an endpoint we know is on the roadmap. Amber, no retry.
    ComingSoon,
    /// 5xx / network blip. Blue/gray, offers a Retry button.
    Retryable,
    /// Terminal (403, decode error, etc). Red, no retry.
    HardError,
}

#[derive(Props, Clone, PartialEq)]
pub struct ErrorCardProps {
    pub variant: ErrorVariant,
    pub title: String,
    pub message: String,
    #[props(default)]
    pub on_retry: Option<EventHandler<()>>,
}

#[component]
pub fn ErrorCard(props: ErrorCardProps) -> Element {
    let (border, bg, text, icon) = match props.variant {
        ErrorVariant::ComingSoon => (
            "border-amber-200 dark:border-amber-700",
            "bg-amber-50 dark:bg-amber-950/30",
            "text-amber-900 dark:text-amber-100",
            "✨",
        ),
        ErrorVariant::Retryable => (
            "border-bunyip-water-200 dark:border-bunyip-water-700",
            "bg-bunyip-water-50 dark:bg-bunyip-water-950/30",
            "text-bunyip-water-900 dark:text-bunyip-water-100",
            "↻",
        ),
        ErrorVariant::HardError => (
            "border-red-200 dark:border-red-800",
            "bg-red-50 dark:bg-red-950/30",
            "text-red-900 dark:text-red-100",
            "!",
        ),
    };

    let on_retry = props.on_retry;

    rsx! {
        div { class: "p-6 rounded-xl border {border} {bg}",
            div { class: "flex items-start gap-3",
                span { class: "shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-base font-bold {text}",
                    "{icon}"
                }
                div { class: "flex-1 min-w-0",
                    p { class: "text-sm font-semibold {text}", "{props.title}" }
                    p { class: "mt-1 text-sm {text} opacity-90", "{props.message}" }
                    if let Some(cb) = on_retry {
                        button {
                            r#type: "button",
                            class: "mt-3 px-3 py-1.5 rounded border border-bunyip-water-300 dark:border-bunyip-water-600 text-sm font-medium {text} hover:bg-white/40 dark:hover:bg-bunyip-reed-900/40",
                            onclick: move |_| cb.call(()),
                            "Retry"
                        }
                    }
                }
            }
        }
    }
}
