//! Content + marketing pages: pricing, our story, terms, privacy, feedback.

use axum::extract::{Multipart, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::auth as auth_api;
use crate::api::calls::{self, FeedbackAttachment, FeedbackInput};
use crate::api::types::SubscriptionTier;
use crate::handlers::dashboard::tier_name;
use crate::handlers::{public_ctx, public_response};
use crate::views::ui::{button_class, icon};
use crate::web::AppState;

/// Displayed at the top of /terms and /privacy. Bump this string the SAME
/// COMMIT you review the policy body for accuracy - do not bump it reflexively
/// to make the page look fresh. The bump is a signal to anyone reading the
/// commit that the policy text was re-read and confirmed current.
const POLICY_LAST_UPDATED: &str = "June 2026";

// --- pricing ----------------------------------------------------------------

const PERSONAL: [&str; 6] = [
    "Single sign-on into Mokosh",
    "Stripe-backed billing and trials",
    "Up to 5 members per org",
    "MFA, magic links, password reset",
    "In-app feedback widget",
    "Cancel anytime",
];
// First bullet phrasing is intentionally tier-name-agnostic ("the personal
// plan" instead of "Starter") so a rename of `SubscriptionTier::Standard`
// via the canonical `tier_name` helper does not desync this feature list
// from the card heading above it.
const BUSINESS: [&str; 6] = [
    "Everything in the personal plan",
    "Unlimited members and orgs",
    "Org switching and role management",
    "Admin console and audit logs",
    "Priority support",
    "Invoice billing",
];

fn pricing_card(
    title: &str,
    desc: &str,
    price: &str,
    features: &[&str],
    highlight: bool,
    stripe: bool,
    cta_href: &str,
    cta_label: &str,
) -> Markup {
    let border = if highlight {
        "w-full border-2 border-primary relative"
    } else {
        "w-full border-primary"
    };
    html! {
        div class={ "rounded-lg border bg-card text-card-foreground shadow-sm " (border) } {
            div class="flex flex-col space-y-1.5 p-6 text-center" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { (title) }
                p class="text-sm text-muted-foreground" { (desc) }
                div class="mt-6" {
                    span class="text-5xl font-bold" { (price) }
                    span class="text-muted-foreground" { "/month" }
                }
                p class="mt-2 text-sm text-muted-foreground" { "Price locked for life when you join" }
            }
            div class="p-6 pt-0" {
                ul class="space-y-4" {
                    @for f in features {
                        li class="flex items-center gap-3" { (icon("check", "h-5 w-5 text-primary flex-shrink-0")) span { (f) } }
                    }
                }
                @if stripe {
                    a href=(cta_href) class=(button_class("default", "lg", "mt-8 w-full")) { (cta_label) }
                } @else {
                    div class="mt-8" {
                        button type="button" disabled title="Payment is not configured" class=(button_class("default", "lg", "w-full")) { (cta_label) }
                    }
                }
                p class="mt-4 text-center text-sm text-muted-foreground" { "30-day grace period if payment fails" }
            }
        }
    }
}

pub async fn pricing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let show_business = st.cfg.show_business_pricing;
    let signed_in = c.is_signed_in();
    let (cta_href, cta_label) = if signed_in {
        ("/membership", "Go to Membership")
    } else {
        ("/register", "Get Started")
    };
    let grid = if show_business {
        "md:grid-cols-2 max-w-4xl"
    } else {
        "max-w-md"
    };

    let content = html! {
        div class="py-20" {
            div class="container" {
                div class="text-center" {
                    h1 class="text-4xl font-bold" { "Simple, transparent pricing" }
                    p class="mt-4 text-lg text-muted-foreground" { "The business layer for your PSA. Start free for 14 days, no credit card required." }
                }
                div class={ "mt-16 grid gap-8 mx-auto " (grid) } {
                    // Route the personal-tier title through tier_name so this
                    // marketing page and the in-app Membership / Settings
                    // labels are byte-identical. Renaming the tier (e.g.
                    // "Standard" -> "Starter") is a one-line change in
                    // `handlers::dashboard::tier_name`.
                    (pricing_card(tier_name(&SubscriptionTier::Standard), "For a single team getting set up", "$3", &PERSONAL, false, stripe, cta_href, cta_label))
                    @if show_business {
                        (pricing_card("Business", "For MSPs running multiple orgs", "$15", &BUSINESS, true, stripe, cta_href, cta_label))
                    }
                }
            }
        }
    };
    public_response(&st, &c, &apps, "Pricing · Bunyip", true, content)
}

// --- our story --------------------------------------------------------------

pub async fn our_story(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-8" { "Our Story" }
            div class="max-w-none space-y-8" {
                section {
                    h2 class="text-2xl font-semibold mb-4" { "Why Bunyip?" }
                    div class="space-y-4 text-muted-foreground" {
                        p { "Mokosh is a focused PSA: the product your MSP actually uses to run service delivery. But every product needs a business layer around it - signup, billing, members, invitations, single sign-on - and that layer is the same boring infrastructure everyone reinvents." }
                        p { "We pulled that layer out into its own surface so the PSA never has to carry it. Bunyip owns identity, subscriptions, and orgs; Mokosh owns the work. Each does one thing well." }
                        p { "The name is the lake cryptid that surfaces what matters. That is the job: lift the business-y bits up out of the product and keep them out of the way." }
                    }
                }
                section {
                    h2 class="text-2xl font-semibold mb-4" { "The business shell" }
                    div class="space-y-4 text-muted-foreground" {
                        p { "Bunyip is the business shell that wraps Mokosh. It is the OIDC entry point, the Stripe-backed billing engine, the org and membership directory, and the admin console - everything around the product, nothing in it." }
                        p { "Your team logs in once through Bunyip and lands in Mokosh. Billing, trials, dunning, MFA, magic links, and trusted devices come out of the box, so the PSA stays focused on what makes your MSP tick." }
                    }
                }
            }
        }
    };
    public_response(&st, &c, &apps, "Our Story · Bunyip", true, content)
}

// --- legal ------------------------------------------------------------------

fn legal_p(title: &str, body: Markup) -> Markup {
    html! { section { h2 class="text-2xl font-semibold mb-4" { (title) } p class="text-muted-foreground" { (body) } } }
}
fn legal_ul(title: &str, items: &[&str]) -> Markup {
    html! {
        section {
            h2 class="text-2xl font-semibold mb-4" { (title) }
            ul class="list-disc pl-6 space-y-2 text-muted-foreground" { @for i in items { li { (i) } } }
        }
    }
}

pub async fn terms(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let d = st.cfg.domain_or_localhost();
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-8" { "Terms of Service" }
            p class="text-muted-foreground mb-8" { "Last updated: " (POLICY_LAST_UPDATED) }
            div class="max-w-none space-y-8" {
                (legal_p("1. Acceptance of Terms", html! { "By accessing or using " (d) " (\"the Service\"), you agree to be bound by these Terms of Service. If you do not agree to these terms, please do not use the Service." }))
                (legal_p("2. Description of Service", html! { (d) " provides a membership-based platform offering access to developer productivity tools." }))
                (legal_ul("3. Membership and Payment", &[
                    "The Service is offered at a flat rate of $3/month for all applications.",
                    "Early adopters who join at this rate will have their price locked for life.",
                    "Payments are processed through Stripe. By joining, you also agree to Stripe's terms of service.",
                    "Memberships renew automatically each month unless cancelled.",
                    "You may cancel your membership at any time through your account settings.",
                    "Upon cancellation, you retain access until the end of your current billing period.",
                ]))
                (legal_p("4. Grace Period", html! { "If a payment fails, you will be granted a 30-day grace period during which you retain full access to the Service. If payment is not resolved within this period, your membership will be cancelled and access will be revoked." }))
                (legal_ul("5. Acceptable Use", &[
                    "Do not use the Service for any illegal or unauthorized purpose.",
                    "Do not attempt to gain unauthorized access to any part of the Service.",
                    "Do not interfere with or disrupt the Service or servers connected to it.",
                    "Do not transmit malware, spam, or other harmful content.",
                ]))
                (legal_p("6. Limitation of Liability", html! { (d) " shall not be liable for any indirect, incidental, special, consequential, or punitive damages resulting from your access to or use of the Service." }))
                (legal_p("7. Contact", html! { "For any questions about these Terms, contact us at " a href=(format!("mailto:support@{d}")) class="text-primary hover:underline" { "support@" (d) } "." }))
            }
        }
    };
    public_response(&st, &c, &apps, "Terms of Service · Bunyip", true, content)
}

pub async fn privacy(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let d = st.cfg.domain_or_localhost();
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-8" { "Privacy Policy" }
            p class="text-muted-foreground mb-8" { "Last updated: " (POLICY_LAST_UPDATED) }
            div class="max-w-none space-y-8" {
                (legal_p("1. Introduction", html! { "This Privacy Policy describes how " (d) " collects, uses, and protects your personal information when you use our services." }))
                (legal_ul("2. Information We Collect", &[
                    "Account Information: Email address, password (hashed), and account preferences.",
                    "Payment Information: Processed securely through Stripe. We do not store full credit card numbers.",
                    "Usage Data: How you interact with our services, features used, and actions taken.",
                    "Cookies: Session cookies for authentication and preferences.",
                ]))
                (legal_ul("3. How We Use Your Information", &[
                    "To provide and maintain our services.",
                    "To process payments and manage memberships.",
                    "To communicate with you about your account and services.",
                    "To prevent fraud and ensure security.",
                    "To comply with legal obligations.",
                ]))
                (legal_ul("4. Data Security", &[
                    "Passwords are hashed using Argon2id.",
                    "All connections are encrypted with TLS/SSL.",
                    "Authentication tokens are cryptographically signed.",
                    "Regular security audits and monitoring.",
                ]))
                (legal_p("5. Your Rights", html! { "You may request access to, correction of, or deletion of your personal data. To exercise these rights, contact us at " a href=(format!("mailto:privacy@{d}")) class="text-primary hover:underline" { "privacy@" (d) } "." }))
                (legal_p("6. Cookies", html! { "We use essential cookies for authentication and session management. We do not use third-party tracking or advertising cookies." }))
            }
        }
    };
    public_response(&st, &c, &apps, "Privacy Policy · Bunyip", true, content)
}

// --- feedback ---------------------------------------------------------------

const FEEDBACK_TAGS: [&str; 4] = ["Bug", "Feature", "Flow", "Idea"];

const FEEDBACK_DEFAULT_PATH: &str = "/feedback";

/// Mirrors bunyip-api's per-form limits (`bunyip-api/src/handlers/feedback.rs:29-35`
/// and lines 151, 161). Enforced upstream of the multipart -> reqwest
/// hop so the user sees an inline error banner rather than the API's
/// bare 422 text after upload completes.
const FEEDBACK_MAX_ATTACHMENTS: usize = 3;
const FEEDBACK_MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
const FEEDBACK_ALLOWED_MIMES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "text/plain",
];
/// Per-route axum body limit on `/feedback`. The default is 2 MB and
/// would reject any reasonable file. Cap at 3 files × 5 MB + ~1 MB of
/// form overhead, rounded up. Applied only to this route in
/// `main.rs`; the rest of the app stays on the default.
pub const FEEDBACK_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// Validate a candidate `page_path` value (from a `?from=` query or from a
/// previously-rendered hidden form field) before round-tripping it back into
/// the markup. Trims, then requires it to start with `/` and stay under the
/// API's 255-char limit (matches the validation at
/// `bunyip-api/src/handlers/feedback.rs:223`). Anything else is treated as
/// missing - cheap open-redirect-style guard for the hidden field.
fn sanitize_page_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') && trimmed.len() <= 255 {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[derive(Deserialize)]
pub struct FeedbackQuery {
    /// Path the visitor came from when they opened the feedback page (e.g.
    /// from the floating launcher or a deep link). Rendered as a hidden
    /// `page_path` input so the submit round-trips it to the API.
    #[serde(default)]
    pub from: Option<String>,
}

fn feedback_form(submitted: bool, error: Option<&str>, page_path: Option<&str>) -> Markup {
    html! {
        div class="relative overflow-hidden py-20" {
            div class="container relative" {
                div class="mx-auto max-w-3xl text-center" {
                    div class="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-4 py-1.5 text-sm text-primary" {
                        (icon("smile-plus", "h-4 w-4")) "Help shape what ships next"
                    }
                    h1 class="mt-6 text-4xl font-bold tracking-tight sm:text-5xl" {
                        "Tell us what would make " span class="text-bunyip-reed-900 dark:text-bunyip-reed-50" { "Bunyip" } " better."
                    }
                    p class="mx-auto mt-4 max-w-2xl text-lg text-muted-foreground" { "Share bugs, missing features, rough edges, or ideas. We read everything." }
                }
                div class="rounded-lg border bg-card text-card-foreground shadow-sm mx-auto mt-12 max-w-2xl border-border/60" {
                    div class="flex flex-col space-y-1.5 p-6" {
                        h3 class="text-2xl font-semibold leading-none tracking-tight" { "Send feedback" }
                        p class="text-sm text-muted-foreground" { "Leave your email if you would like a follow-up." }
                    }
                    div class="p-6 pt-0" {
                        @if submitted {
                            div class="mb-6 rounded-lg border border-teal-500/40 bg-teal-500/10 p-4 text-sm text-teal-700 dark:text-teal-300" { "Thanks for sharing. Your feedback has been sent to the team." }
                        }
                        @if let Some(e) = error {
                            div class="mb-6 rounded-lg border border-destructive/50 p-4 text-sm text-destructive" { (e) }
                        }
                        // `enctype="multipart/form-data"` is required so the
                        // file input below can carry binary file parts. The
                        // form-handler reads via axum's Multipart extractor.
                        form method="post" action="/feedback" enctype="multipart/form-data" class="space-y-5" {
                            div class="grid gap-5 md:grid-cols-2" {
                                div class="grid gap-2" { label for="name" class="text-sm font-medium" { "Name" } input id="name" name="name" placeholder="Optional" class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"; }
                                div class="grid gap-2" { label for="email" class="text-sm font-medium" { "Email" } input id="email" name="email" type="email" placeholder="you@example.com" class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"; }
                            }
                            div class="grid gap-2" { label for="subject" class="text-sm font-medium" { "Subject" } input id="subject" name="subject" placeholder="Optional" class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"; }
                            div class="grid gap-3" {
                                label class="text-sm font-medium" { "Tags" }
                                div class="flex flex-wrap gap-3" {
                                    @for tag in FEEDBACK_TAGS {
                                        label class="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm cursor-pointer" {
                                            input type="checkbox" name="tags" value=(tag) class="h-4 w-4"; (tag)
                                        }
                                    }
                                }
                            }
                            div class="hidden" { input name="website" autocomplete="off" tabindex="-1"; }
                            @if let Some(p) = page_path {
                                input type="hidden" name="page_path" value=(p);
                            }
                            div class="grid gap-2" {
                                label for="message" class="text-sm font-medium" { "Message" }
                                textarea id="message" name="message" rows="7" required placeholder="What would you like to see improved?" class="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                            }
                            div class="grid gap-2" {
                                label for="attachments" class="text-sm font-medium" { "Attachments " span class="text-muted-foreground font-normal" { "(optional)" } }
                                input id="attachments" name="attachments" type="file" multiple
                                    accept="image/png,image/jpeg,image/webp,image/gif,text/plain"
                                    class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm file:mr-3 file:rounded file:border-0 file:bg-muted file:px-3 file:py-1 file:text-sm";
                                p class="text-xs text-muted-foreground" { "PNG, JPEG, WebP, GIF, or plain text. Up to 3 files, 5 MB each." }
                            }
                            div class="flex justify-end" {
                                button type="submit" class=(button_class("default", "default", "gap-2")) { "Send feedback" }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn feedback_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FeedbackQuery>,
) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let from = q.from.as_deref().and_then(sanitize_page_path);
    public_response(
        &st,
        &c,
        &apps,
        "Feedback · Bunyip",
        false,
        feedback_form(false, None, from.as_deref()),
    )
}

/// Consume the multipart body into a [`FeedbackInput`].
///
/// On a per-form ceiling violation (too many files, oversize file,
/// disallowed MIME) returns `Err(message)` so the caller can re-render
/// the form with the standard inline error banner. Skips files
/// produced by an empty input (the browser sends a zero-length
/// `application/octet-stream` part for empty file slots), preserves
/// repeated `tags` keys for the multi-checkbox row, sanitizes
/// `page_path` the same way the previous `application/x-www-form-urlencoded`
/// parser did, and tolerates unknown text fields silently.
///
/// Pure I/O error path: an underlying multipart read failure (likely
/// a malformed body or a connection drop mid-upload) also becomes an
/// inline `Err`, mirroring the BUNYIP-79 "graceful 422 -> inline"
/// posture for the old text-only form.
async fn read_feedback_multipart(multipart: &mut Multipart) -> Result<FeedbackInput, String> {
    let mut input = FeedbackInput {
        name: String::new(),
        email: String::new(),
        subject: String::new(),
        message: String::new(),
        tags: Vec::new(),
        page_path: FEEDBACK_DEFAULT_PATH.into(),
        website: String::new(),
        attachments: Vec::new(),
    };
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Err(format!("Could not read form: {e}")),
        };
        let field_name = field.name().map(str::to_string).unwrap_or_default();
        let file_name = field.file_name().map(str::to_string);
        let content_type = field.content_type().map(str::to_string);
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(format!("Could not read field: {e}")),
        };
        if let Some(filename) = file_name {
            // File field. The browser sends a zero-length part for
            // every empty file input slot; skip those instead of
            // turning them into a "0-byte file" the API would reject.
            if bytes.is_empty() {
                continue;
            }
            if bytes.len() > FEEDBACK_MAX_ATTACHMENT_BYTES {
                return Err(format!(
                    "Each attachment must be {} MB or smaller. \"{filename}\" exceeds the limit.",
                    FEEDBACK_MAX_ATTACHMENT_BYTES / (1024 * 1024)
                ));
            }
            if input.attachments.len() >= FEEDBACK_MAX_ATTACHMENTS {
                return Err(format!(
                    "Up to {FEEDBACK_MAX_ATTACHMENTS} attachments only."
                ));
            }
            let mime = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
            if !FEEDBACK_ALLOWED_MIMES.contains(&mime.as_str()) {
                return Err("Only PNG, JPEG, WebP, GIF, and plain text files are allowed.".into());
            }
            // Strip path separators - safe filename only. Matches the
            // API's sanitization at `bunyip-api/src/handlers/feedback.rs:177-181`.
            let safe = std::path::Path::new(&filename)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment")
                .to_string();
            input.attachments.push(FeedbackAttachment {
                filename: safe,
                mime,
                bytes: bytes.to_vec(),
            });
            continue;
        }
        let value = String::from_utf8_lossy(&bytes).to_string();
        match field_name.as_str() {
            "name" => input.name = value,
            "email" => input.email = value,
            "subject" => input.subject = value,
            "message" => input.message = value,
            "website" => input.website = value,
            "page_path" => {
                if let Some(p) = sanitize_page_path(&value) {
                    input.page_path = p;
                }
            }
            "tags" => {
                let s = value.trim();
                if !s.is_empty() {
                    input.tags.push(s.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(input)
}

pub async fn feedback_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let (c, apps) = public_ctx(&st, &headers).await;
    let cookie = c.forward.clone();
    let parsed = read_feedback_multipart(&mut multipart).await;
    let (submitted, error, render_path) = match parsed {
        Err(msg) => (false, Some(msg), None),
        Ok(input) => {
            // Round-trip the captured path on error redraw so the next submit
            // attempt keeps the context (otherwise a typo on the message field
            // would strip the `?from=` context after the first failed submit).
            let render_path = if input.page_path == FEEDBACK_DEFAULT_PATH {
                None
            } else {
                Some(input.page_path.clone())
            };
            if input.message.trim().is_empty() {
                (
                    false,
                    Some("Please enter a message.".to_string()),
                    render_path,
                )
            } else {
                match calls::submit_feedback(&st.api, cookie.as_deref(), &input).await {
                    Ok(()) => (true, None, render_path),
                    Err(e) => (false, Some(e.user_message()), render_path),
                }
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        "Feedback · Bunyip",
        false,
        feedback_form(submitted, error.as_deref(), render_path.as_deref()),
    )
}
