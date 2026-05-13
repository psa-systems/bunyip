//! Public `/feedback` page. Mirrors the saas FeedbackPage:
//! - Big hero with gradient background.
//! - Tag chips (Bug / Feature / Flow / Idea) - multi-select.
//! - Name, email, subject, message fields. Message required, rest optional.
//! - Hidden honeypot `website` field for bot detection.
//! - Submit posts to `/v1/feedback`.

use dioxus::prelude::*;

use crate::api::feedback::{self, SubmitRequest};
use crate::components::layout::PublicNav;
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};
use crate::stores::toast::use_toast;

const TAGS: &[(&str, &str, &str)] = &[
    ("Bug", "border-red-300 text-red-700", "bg-red-50 border-red-500 text-red-800"),
    ("Feature", "border-bunyip-water-300 text-bunyip-water-700", "bg-bunyip-water-100 border-bunyip-water-500 text-bunyip-water-700"),
    ("Flow", "border-amber-300 text-amber-700", "bg-amber-50 border-amber-500 text-amber-800"),
    ("Idea", "border-bunyip-reed-300 text-bunyip-reed-700", "bg-bunyip-reed-100 border-bunyip-reed-500 text-bunyip-reed-800"),
];

#[component]
pub fn FeedbackPage() -> Element {
    let toast = use_toast();
    let auth = use_auth();

    // Prefill name/email if the user is signed in.
    let initial_name = match &*auth.read() {
        AuthState::SignedIn(me) => me.user.name.clone(),
        _ => String::new(),
    };
    let initial_email = match &*auth.read() {
        AuthState::SignedIn(me) => me.user.email.clone(),
        _ => String::new(),
    };

    let mut name = use_signal(|| initial_name);
    let mut email = use_signal(|| initial_email);
    let mut subject = use_signal(String::new);
    let mut message = use_signal(String::new);
    let mut tags = use_signal(Vec::<String>::new);
    // Honeypot - hidden via CSS; bots will fill it, real users won't.
    let mut website = use_signal(String::new);

    let mut submitting = use_signal(|| false);
    let mut submitted = use_signal(|| false);

    let page_path = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.referrer().split('/').collect::<Vec<_>>().into_iter().skip(3).collect::<Vec<_>>().join("/").into())
        .map(|s: String| if s.is_empty() { None } else { Some(format!("/{}", s)) })
        .unwrap_or(None);

    let toggle_tag = move |tag: String| {
        let mut current = tags.write();
        if let Some(idx) = current.iter().position(|t| t == &tag) {
            current.remove(idx);
        } else {
            current.push(tag);
        }
    };

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        if message().trim().is_empty() {
            toast.error("Message is required.");
            return;
        }
        let req = SubmitRequest {
            name: opt(name()),
            email: opt(email()),
            subject: opt(subject()),
            tags: tags(),
            message: message(),
            page_path: page_path.clone(),
            website: opt(website()),
            attachments: Vec::new(),
        };
        spawn(async move {
            submitting.set(true);
            match feedback::submit(&req).await {
                Ok(_) => {
                    submitted.set(true);
                    message.set(String::new());
                    subject.set(String::new());
                    tags.set(Vec::new());
                    toast.success("Thanks for the feedback.");
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        div { class: "min-h-screen flex flex-col bg-gradient-to-b from-bunyip-reed-50 to-white",
            PublicNav {}

            section { class: "relative overflow-hidden flex-1 px-6 py-16",
                // Decorative gradient blobs.
                div { class: "pointer-events-none absolute -top-32 -right-24 w-96 h-96 rounded-full bg-bunyip-water-100 blur-3xl opacity-60" }
                div { class: "pointer-events-none absolute -bottom-32 -left-24 w-96 h-96 rounded-full bg-bunyip-reed-100 blur-3xl opacity-70" }

                div { class: "relative max-w-3xl mx-auto",
                    div { class: "text-center",
                        span { class: "inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-bunyip-reed-200 bg-bunyip-reed-50 text-bunyip-reed-700 text-sm",
                            HeartIcon {}
                            "Help shape what ships next"
                        }
                        h1 { class: "mt-6 text-4xl sm:text-5xl font-bold tracking-tight text-bunyip-reed-900",
                            "Tell us what would make "
                            span { class: "bg-gradient-to-r from-bunyip-reed-700 via-bunyip-water-700 to-bunyip-water-500 bg-clip-text text-transparent",
                                "Bunyip"
                            }
                            " better."
                        }
                        p { class: "mt-4 text-lg text-bunyip-reed-700",
                            "Share bugs, missing features, rough edges, or ideas. We read everything."
                        }
                    }

                    div { class: "mt-10 rounded-2xl border border-bunyip-reed-100 bg-white shadow-lg shadow-bunyip-reed-100/40 p-6 md:p-8",
                        h2 { class: "text-xl font-semibold text-bunyip-reed-900", "Send feedback" }
                        p { class: "mt-1 text-sm text-bunyip-reed-700",
                            "Leave your email if you would like a follow-up. We kept this form simple so it is easy to share what is on your mind."
                        }

                        if submitted() {
                            div { class: "mt-6 p-4 rounded-lg border border-bunyip-reed-200 bg-bunyip-reed-50",
                                p { class: "font-semibold text-bunyip-reed-900", "Feedback sent" }
                                p { class: "mt-1 text-sm text-bunyip-reed-700",
                                    "Thanks for sharing. Your feedback has been sent to the team. "
                                    Link { to: Route::LandingPage {}, class: "underline", "Back to home" }
                                    " · "
                                    button {
                                        class: "underline",
                                        onclick: move |_| submitted.set(false),
                                        "Send another"
                                    }
                                }
                            }
                        }

                        form { class: "mt-6 space-y-5", onsubmit: submit,
                            div { class: "grid sm:grid-cols-2 gap-4",
                                Field {
                                    label: "Name",
                                    placeholder: "Optional",
                                    value: name(),
                                    oninput: move |v| name.set(v),
                                }
                                Field {
                                    label: "Email",
                                    placeholder: "Optional - for follow-up",
                                    value: email(),
                                    oninput: move |v| email.set(v),
                                    input_type: "email",
                                }
                            }

                            Field {
                                label: "Subject",
                                placeholder: "Optional - a quick summary",
                                value: subject(),
                                oninput: move |v| subject.set(v),
                            }

                            div {
                                p { class: "text-sm font-medium text-bunyip-reed-800", "Tags" }
                                p { class: "mt-1 text-xs text-bunyip-reed-600", "Pick any that apply." }
                                div { class: "mt-2 flex flex-wrap gap-2",
                                    for (tag, idle_class, selected_class) in TAGS.iter() {
                                        {
                                            let is_selected = tags().iter().any(|t| t == tag);
                                            let class = if is_selected { *selected_class } else { *idle_class };
                                            let tag_str = tag.to_string();
                                            let mut toggle = toggle_tag;
                                            rsx! {
                                                button {
                                                    r#type: "button",
                                                    class: "px-3 py-1.5 rounded-full border text-sm font-medium transition-colors {class}",
                                                    onclick: move |_| toggle(tag_str.clone()),
                                                    "{tag}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            div {
                                label { class: "block",
                                    span { class: "text-sm font-medium text-bunyip-reed-800", "Message" }
                                    textarea {
                                        class: "mt-1 w-full min-h-[140px] px-3 py-2 rounded border border-bunyip-reed-200 bg-white focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                        placeholder: "What happened? What did you want to do? What surprised you?",
                                        value: "{message()}",
                                        oninput: move |evt| message.set(evt.value()),
                                    }
                                }
                            }

                            // Honeypot - hidden from real users via aria + tabindex.
                            div { class: "absolute -left-[9999px] opacity-0 pointer-events-none",
                                "aria-hidden": "true",
                                label {
                                    "Website (leave empty)"
                                    input {
                                        r#type: "text",
                                        tabindex: "-1",
                                        autocomplete: "off",
                                        value: "{website()}",
                                        oninput: move |evt| website.set(evt.value()),
                                    }
                                }
                            }

                            button {
                                class: "w-full px-4 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                                r#type: "submit",
                                disabled: submitting(),
                                if submitting() { "Sending…" } else { "Send feedback" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn opt(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

#[component]
fn Field(
    label: &'static str,
    placeholder: &'static str,
    value: String,
    oninput: EventHandler<String>,
    #[props(default = "text")] input_type: &'static str,
) -> Element {
    rsx! {
        label { class: "block",
            span { class: "text-sm font-medium text-bunyip-reed-800", "{label}" }
            input {
                class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 bg-white focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                r#type: "{input_type}",
                placeholder: "{placeholder}",
                value: "{value}",
                oninput: move |evt| oninput.call(evt.value()),
            }
        }
    }
}

#[component]
fn HeartIcon() -> Element {
    rsx! {
        svg {
            class: "w-4 h-4",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M21 8.5c0 4.5-9 11.5-9 11.5S3 13 3 8.5A4.5 4.5 0 017.5 4c2 0 3.3 1 4.5 2.6C13.2 5 14.5 4 16.5 4A4.5 4.5 0 0121 8.5z" }
            circle { cx: "8.5", cy: "10", r: "0.8", fill: "currentColor" }
            circle { cx: "12", cy: "11.5", r: "0.8", fill: "currentColor" }
            circle { cx: "15.5", cy: "10", r: "0.8", fill: "currentColor" }
        }
    }
}
