//! Platform-admin pages. Gated by `users.role = "admin"` on the backend - the
//! frontend just renders a "forbidden" notice if the API returns 403.

use dioxus::prelude::*;

use crate::api::feedback::{self, Feedback, FeedbackStatus};
use crate::components::layout::AppShell;
use crate::stores::toast::use_toast;

#[component]
pub fn AdminFeedbackPage() -> Element {
    let toast = use_toast();
    let mut filter = use_signal(|| "all".to_string());
    let mut refresh_key = use_signal(|| 0u64);

    let feedback_resource = use_resource(move || {
        let filter = filter();
        let _ = refresh_key.read();
        async move {
            feedback::list_admin(if filter == "all" { None } else { Some(&filter) }).await
        }
    });

    rsx! {
        AppShell { title: "Admin · Feedback".to_string(),
            div { class: "max-w-5xl mx-auto",
                h1 { class: "text-2xl font-bold tracking-tight text-bunyip-reed-900", "Feedback inbox" }
                p { class: "mt-1 text-sm text-bunyip-reed-700",
                    "Triage and close in-app feedback. Requires admin role."
                }

                div { class: "mt-4 flex gap-2",
                    FilterChip { current: filter(), value: "all", label: "All", onpick: move |s| filter.set(s) }
                    FilterChip { current: filter(), value: "new", label: "New", onpick: move |s| filter.set(s) }
                    FilterChip { current: filter(), value: "triaged", label: "Triaged", onpick: move |s| filter.set(s) }
                    FilterChip { current: filter(), value: "closed", label: "Closed", onpick: move |s| filter.set(s) }
                }

                div { class: "mt-6 rounded-xl border border-bunyip-reed-100 bg-white",
                    match &*feedback_resource.read_unchecked() {
                        None => rsx! { p { class: "p-6 text-sm text-bunyip-reed-700", "Loading…" } },
                        Some(Err(e)) => rsx! { p { class: "p-6 text-sm text-red-700", "{e.user_message()}" } },
                        Some(Ok(list)) if list.is_empty() => rsx! { p { class: "p-6 text-sm text-bunyip-reed-600", "Nothing here yet." } },
                        Some(Ok(list)) => rsx! {
                            ul { class: "divide-y divide-bunyip-reed-50",
                                for entry in list.iter() {
                                    FeedbackRow { entry: entry.clone(), refresh_key: refresh_key, toast: toast }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FilterChip(
    current: String,
    value: &'static str,
    label: &'static str,
    onpick: EventHandler<String>,
) -> Element {
    let active = current == value;
    let class = if active {
        "px-3 py-1.5 rounded-full bg-bunyip-reed-700 text-white text-xs font-medium"
    } else {
        "px-3 py-1.5 rounded-full border border-bunyip-reed-200 text-bunyip-reed-800 text-xs hover:bg-bunyip-reed-50"
    };
    rsx! {
        button {
            class: "{class}",
            onclick: move |_| onpick.call(value.to_string()),
            "{label}"
        }
    }
}

#[component]
fn FeedbackRow(entry: Feedback, refresh_key: Signal<u64>, toast: crate::stores::toast::ToastStore) -> Element {
    let mut refresh_key = refresh_key;
    let id_close = entry.id.clone();
    let id_triage = entry.id.clone();
    let id_reopen = entry.id.clone();

    let close = move |_| {
        let id = id_close.clone();
        spawn(async move {
            match feedback::update_status(&id, FeedbackStatus::Closed).await {
                Ok(()) => { toast.success("Closed."); refresh_key.set(refresh_key() + 1); }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };
    let triage = move |_| {
        let id = id_triage.clone();
        spawn(async move {
            match feedback::update_status(&id, FeedbackStatus::Triaged).await {
                Ok(()) => { toast.info("Marked triaged."); refresh_key.set(refresh_key() + 1); }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };
    let reopen = move |_| {
        let id = id_reopen.clone();
        spawn(async move {
            match feedback::update_status(&id, FeedbackStatus::New).await {
                Ok(()) => { toast.info("Reopened."); refresh_key.set(refresh_key() + 1); }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let (status_label, status_class) = match entry.status {
        FeedbackStatus::New => ("New", "bg-bunyip-water-700 text-white"),
        FeedbackStatus::Triaged => ("Triaged", "bg-bunyip-reed-100 text-bunyip-reed-800"),
        FeedbackStatus::Closed => ("Closed", "bg-bunyip-reed-50 text-bunyip-reed-700"),
    };
    let tags_view = entry.tags.clone();

    rsx! {
        li { class: "p-5",
            div { class: "flex items-start justify-between gap-3",
                div { class: "flex-1 min-w-0",
                    div { class: "flex flex-wrap items-center gap-2",
                        for t in tags_view.iter() {
                            span { class: "px-2 py-0.5 rounded-full text-xs font-medium uppercase tracking-wide bg-bunyip-reed-50 border border-bunyip-reed-100 text-bunyip-reed-700",
                                "{t}"
                            }
                        }
                        if let Some(s) = &entry.subject {
                            span { class: "text-sm font-semibold text-bunyip-reed-900", "{s}" }
                        }
                    }
                    p { class: "mt-2 text-sm text-bunyip-reed-900 whitespace-pre-wrap",
                        "{entry.message}"
                    }
                    p { class: "mt-2 text-xs text-bunyip-reed-600",
                        if let Some(name) = &entry.name {
                            "{name}"
                            if let Some(e) = &entry.email { " <" "{e}" "> · " }
                            else { " · " }
                        }
                        if let Some(r) = &entry.page_path { "Page " span { class: "font-mono", "{r}" } " · " }
                        "Submitted "
                        span { class: "font-mono", "{format_date(&entry.created_at)}" }
                        if let Some(url) = &entry.forgejo_issue_url {
                            " · "
                            a { class: "underline", href: "{url}", "Forgejo issue" }
                        }
                    }
                }
                span { class: "shrink-0 px-2 py-0.5 rounded-full text-xs uppercase tracking-wide font-semibold {status_class}",
                    "{status_label}"
                }
            }
            div { class: "mt-3 flex gap-2 justify-end",
                match entry.status {
                    FeedbackStatus::New => rsx! {
                        button { class: "px-3 py-1.5 rounded border border-bunyip-reed-200 text-sm hover:bg-bunyip-reed-50", onclick: triage, "Mark triaged" }
                        button { class: "px-3 py-1.5 rounded border border-bunyip-reed-200 text-sm hover:bg-bunyip-reed-50", onclick: close, "Close" }
                    },
                    FeedbackStatus::Triaged => rsx! {
                        button { class: "px-3 py-1.5 rounded border border-bunyip-reed-200 text-sm hover:bg-bunyip-reed-50", onclick: close, "Close" }
                    },
                    FeedbackStatus::Closed => rsx! {
                        button { class: "px-3 py-1.5 rounded border border-bunyip-reed-200 text-sm hover:bg-bunyip-reed-50", onclick: reopen, "Reopen" }
                    },
                }
            }
        }
    }
}

fn format_date(ts: &str) -> String {
    ts.split('T').next().unwrap_or(ts).to_string()
}
