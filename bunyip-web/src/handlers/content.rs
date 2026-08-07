//! Content + marketing pages: pricing, our story, terms, privacy, feedback.

use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;

use crate::api::auth as auth_api;
use crate::api::calls::{self, FeedbackAttachment, FeedbackInput};
use crate::api::types::PricingResponse;
use crate::handlers::dashboard::tier_name;
use crate::handlers::{dashboard_input, public_ctx, public_response};
use crate::util::format_stripe_amount;
use crate::views::ui::{button_class, empty_state, error_box, icon, success_box};
use crate::web::AppState;

/// Displayed at the top of /terms and /privacy. Bump this string the SAME
/// COMMIT you review the policy body for accuracy - do not bump it reflexively
/// to make the page look fresh. The bump is a signal to anyone reading the
/// commit that the policy text was re-read and confirmed current.
const POLICY_LAST_UPDATED: &str = "June 2026";

// --- pricing ----------------------------------------------------------------

// BUNYIP-487: "Up to 5 members per org" is gone. There is no orgs table and no
// membership cap in the product, so the bullet advertised something that does
// not exist.
const PERSONAL: [&str; 5] = [
    "Single sign-on into Mokosh",
    "Stripe-backed billing and trials",
    "MFA, magic links, password reset",
    "In-app feedback widget",
    "Cancel anytime",
];

/// Trial length sentence fragment, from `tier_config.standard_trial_days`.
/// BUNYIP-487: the page used to say "14 days" while the configured default was
/// 30, so the marketing copy advertised a trial the application did not honour.
/// `0` means the length is unknown (the API did not answer), so the copy drops
/// the number rather than inventing one.
pub(super) fn trial_phrase(days: i64) -> String {
    if days > 0 {
        format!("free for {days} days")
    } else {
        "free".to_string()
    }
}

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
                        li class="flex items-center gap-3" { (icon("check", "h-5 w-5 text-primary-text flex-shrink-0")) span { (f) } }
                    }
                }
                @if stripe {
                    a href=(cta_href) class=(button_class("default", "lg", "mt-8 w-full")) { (cta_label) }
                } @else {
                    div class="mt-8" {
                        button type="button" disabled title="Payment is not configured" class=(button_class("default", "lg", "w-full")) { (cta_label) }
                    }
                }
                // Policy constant, not tier configuration: it matches the Terms
                // of Service text further down this module.
                p class="mt-4 text-center text-sm text-muted-foreground" { "30-day grace period if payment fails" }
            }
        }
    }
}

/// The pricing page body. Split out from the handler so the rendering is unit
/// testable against a `PricingResponse` without an API round trip.
pub(super) fn pricing_content(pricing: &PricingResponse, stripe: bool, signed_in: bool) -> Markup {
    let (cta_href, cta_label) = if signed_in {
        ("/membership", "Go to Membership")
    } else {
        ("/register", "Sign up")
    };
    let grid = if pricing.tiers.len() > 1 {
        "md:grid-cols-2 max-w-4xl"
    } else {
        "max-w-md"
    };
    html! {
        div class="py-20" {
            div class="container" {
                div class="text-center" {
                    h1 class="text-4xl font-bold" { "Simple, transparent pricing" }
                    p class="mt-4 text-lg text-muted-foreground" {
                        "The business layer for your PSA. Start " (trial_phrase(pricing.trial_days)) ", no credit card required."
                    }
                }
                div class={ "mt-16 grid gap-8 mx-auto " (grid) } {
                    @for t in &pricing.tiers {
                        // Route the tier title through tier_name so this
                        // marketing page and the in-app Membership / Settings
                        // labels are byte-identical. Renaming the tier (e.g.
                        // "Standard" -> "Starter") is a one-line change in
                        // `handlers::dashboard::tier_name`.
                        (pricing_card(
                            tier_name(&t.tier),
                            "Everything around the product, nothing in it",
                            &format_stripe_amount(Some(t.amount), &t.currency),
                            &PERSONAL,
                            false,
                            stripe,
                            cta_href,
                            cta_label,
                        ))
                    }
                }
            }
        }
    }
}

/// BUNYIP-487: 404 unless an admin published pricing AND a tier resolves to a
/// usable Stripe price. A pricing page with no pricing has nothing to say, and
/// the nav / footer / hero links are hidden on exactly the same condition.
pub async fn pricing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    if !pricing.published() {
        let mut resp = public_response(
            &st,
            &c,
            &apps,
            &pricing,
            "Not found · Bunyip",
            false,
            crate::handlers::public::not_found_content(),
        );
        *resp.status_mut() = axum::http::StatusCode::NOT_FOUND;
        return resp;
    }
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let content = pricing_content(&pricing, stripe, c.is_signed_in());
    public_response(&st, &c, &apps, &pricing, "Pricing · Bunyip", true, content)
}

// --- our story --------------------------------------------------------------

pub async fn our_story(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-8" { "Our Story" }
            div class="max-w-none space-y-8" {
                section {
                    h2 class="text-2xl font-semibold mb-4" { "Why Bunyip?" }
                    div class="space-y-4 text-muted-foreground" {
                        p { "Mokosh is a focused PSA: the product your MSP actually uses to run service delivery. But every product needs a business layer around it - signup, billing, members, invitations, single sign-on - and that layer is the same boring infrastructure everyone reinvents." }
                        p { "We pulled that layer out into its own surface so the PSA never has to carry it. Bunyip owns identity, subscriptions, and memberships; Mokosh owns the work. Each does one thing well." }
                        p { "The name is the lake cryptid that surfaces what matters. That is the job: lift the business-y bits up out of the product and keep them out of the way." }
                    }
                }
                section {
                    h2 class="text-2xl font-semibold mb-4" { "The business shell" }
                    div class="space-y-4 text-muted-foreground" {
                        p { "Bunyip is the business shell that wraps Mokosh. It is the OIDC entry point, the Stripe-backed billing engine, the membership and entitlement directory, and the admin console - everything around the product, nothing in it." }
                        p { "Your team logs in once through Bunyip and lands in Mokosh. Billing, trials, dunning, MFA, magic links, and trusted devices come out of the box, so the PSA stays focused on what makes your MSP tick." }
                    }
                }
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        "Our Story · Bunyip",
        true,
        content,
    )
}

// --- roadmap ----------------------------------------------------------------

// Seed roadmap items, grouped by status bucket. Each entry is a (title,
// one-line description) pair. Editing the page is a one-line change here,
// the same shape as PERSONAL above. Placeholder content until a
// data-backed source lands (see BUNYIP-136); keep copy in American English
// with no em-dashes.
const ROADMAP_SHIPPING_SOON: [(&str, &str); 2] = [
    (
        "Single sign-on hardening",
        "Tighter session rotation and trusted-device controls across Bunyip and Mokosh.",
    ),
    (
        "Org switching polish",
        "Faster switching between orgs with clearer role and membership context.",
    ),
];
const ROADMAP_PLANNED: [(&str, &str); 2] = [
    (
        "Org-level billing roles",
        "Delegate billing and invoices to a finance contact without granting full admin.",
    ),
    (
        "Usage and audit exports",
        "Download audit logs and membership history as CSV.",
    ),
];
const ROADMAP_EXPLORING: [(&str, &str); 2] = [
    (
        "Self-serve org migration",
        "Move members and entitlements between orgs without support involvement.",
    ),
    (
        "Public status page",
        "A live view of platform availability and incident history.",
    ),
];

fn roadmap_section(title: &str, blurb: &str, items: &[(&str, &str)]) -> Markup {
    html! {
        section {
            h2 class="text-2xl font-semibold mb-2" { (title) }
            p class="text-muted-foreground mb-6" { (blurb) }
            div class="grid gap-4 md:grid-cols-2" {
                @for (name, desc) in items {
                    div class="rounded-lg border bg-card text-card-foreground shadow-sm p-6" {
                        div class="flex items-start gap-3" {
                            (icon("check", "h-5 w-5 text-primary-text flex-shrink-0 mt-0.5"))
                            div {
                                h3 class="font-semibold leading-none tracking-tight" { (name) }
                                p class="mt-2 text-sm text-muted-foreground" { (desc) }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub async fn roadmap(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let content = html! {
        div class="container max-w-4xl py-12" {
            div class="mb-12" {
                h1 class="text-4xl font-bold mb-4" { "Roadmap" }
                p class="text-lg text-muted-foreground" { "What we are working on and what is coming next. This is a living view, so expect it to change as we ship." }
            }
            div class="space-y-12" {
                (roadmap_section("Shipping soon", "In progress and landing in the near term.", &ROADMAP_SHIPPING_SOON))
                (roadmap_section("Planned", "Committed work that has not started yet.", &ROADMAP_PLANNED))
                (roadmap_section("Exploring", "Ideas we are considering. No commitment yet.", &ROADMAP_EXPLORING))
            }
        }
    };
    public_response(&st, &c, &apps, &pricing, "Roadmap · Bunyip", true, content)
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
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
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
                (legal_p("7. Contact", html! { "For any questions about these Terms, contact us at " a href=(format!("mailto:support@{d}")) class="text-primary-text hover:underline" { "support@" (d) } "." }))
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        "Terms of Service · Bunyip",
        true,
        content,
    )
}

pub async fn privacy(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
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
                (legal_p("5. Your Rights", html! { "You may request access to, correction of, or deletion of your personal data. To exercise these rights, contact us at " a href=(format!("mailto:privacy@{d}")) class="text-primary-text hover:underline" { "privacy@" (d) } "." }))
                (legal_p("6. Cookies", html! { "We use essential cookies for authentication and session management. We do not use third-party tracking or advertising cookies." }))
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        "Privacy Policy · Bunyip",
        true,
        content,
    )
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
                    div class="inline-flex items-center gap-2 rounded-full bg-brand-primary-100 dark:bg-brand-primary-800 px-4 py-1.5 text-sm font-medium text-brand-primary-800 dark:text-brand-primary-100" {
                        (icon("smile-plus", "h-4 w-4")) "Help shape what ships next"
                    }
                    h1 class="mt-6 text-4xl font-bold tracking-tight sm:text-5xl" {
                        "Tell us what would make " span class="text-brand-primary-900 dark:text-brand-primary-50" { "Bunyip" } " better."
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
                            div class="mb-6" { (success_box("Thanks for sharing. Your feedback has been sent to the team.")) }
                        }
                        @if let Some(e) = error {
                            div class="mb-6" { (error_box(e)) }
                        }
                        // `enctype="multipart/form-data"` is required so the
                        // file input below can carry binary file parts. The
                        // form-handler reads via axum's Multipart extractor.
                        form method="post" action="/feedback" enctype="multipart/form-data" class="space-y-4" {
                            div class="grid gap-4 md:grid-cols-2" {
                                div class="grid gap-2" { label for="name" class="text-sm font-medium" { "Name" } input id="name" name="name" maxlength="100" placeholder="Optional" class=(dashboard_input()); }
                                div class="grid gap-2" { label for="email" class="text-sm font-medium" { "Email" } input id="email" name="email" type="email" maxlength="254" placeholder="you@example.com" class=(dashboard_input()); }
                            }
                            div class="grid gap-2" { label for="subject" class="text-sm font-medium" { "Subject" } input id="subject" name="subject" maxlength="200" placeholder="Optional" class=(dashboard_input()); }
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
                                textarea id="message" name="message" rows="7" required maxlength="16000" placeholder="What would you like to see improved?" class={ (dashboard_input()) " min-h-[168px]" } {}
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
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let from = q.from.as_deref().and_then(sanitize_page_path);
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
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
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
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
            // BUNYIP-115: web-edge validation. Bound each field to its DB
            // VARCHAR cap (feedback.name VARCHAR(100), subject VARCHAR(200),
            // email VARCHAR(255), message TEXT/64k cap below) and shape-check
            // email. Over-length input used to hit the API and surface as a
            // raw 500 when Postgres rejected the over-length value; malformed
            // email round-tripped without complaint.
            use crate::handlers::validate;
            const MESSAGE_MAX: usize = 16_000;
            let mut err: Option<String> = None;
            if !input.name.trim().is_empty() {
                if let Err(msg) = validate::trim_bounded(&input.name, "Name", 100) {
                    err = Some(msg);
                }
            }
            if err.is_none() && !input.email.trim().is_empty() {
                if let Err(msg) = validate::email(&input.email, "Email") {
                    err = Some(msg);
                }
            }
            if err.is_none() && !input.subject.trim().is_empty() {
                if let Err(msg) = validate::trim_bounded(&input.subject, "Subject", 200) {
                    err = Some(msg);
                }
            }
            if err.is_none() {
                if input.message.trim().is_empty() {
                    err = Some("Please enter a message.".to_string());
                } else if input.message.len() > MESSAGE_MAX {
                    err = Some(format!("Message must be {MESSAGE_MAX} characters or fewer"));
                }
            }
            match err {
                Some(msg) => (false, Some(msg), render_path),
                None => match calls::submit_feedback(&st.api, cookie.as_deref(), &input).await {
                    Ok(()) => (true, None, render_path),
                    Err(e) => (false, Some(e.user_message()), render_path),
                },
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        "Feedback · Bunyip",
        false,
        feedback_form(submitted, error.as_deref(), render_path.as_deref()),
    )
}

// --- docs (BUNYIP-385, curated for users in BUNYIP-387) ---------------------
//
// Public PRODUCT docs under /docs, for people using Bunyip to access and
// download apps (e.g. Mokosh). This set is user-facing by design: internal
// developer runbooks (e2e, sqlx checksums, dev-sso, client-IP forwarding,
// Stripe test mode, the OCI verification runbook) live under the repo `docs/`
// and `docs/dev-docs/`, NOT here - do not surface them at /docs. The markdown
// is embedded from `bunyip-web/src/docs/*.md`. Temporary home until the
// dedicated docs app matures (then repoint /docs there, or 301); this whole
// module retires with that cutover.

/// (slug, title, markdown) for each doc surfaced under /docs.
const DOCS: &[(&str, &str, &str)] = &[
    (
        "getting-started",
        "Getting Started",
        include_str!("../docs/getting-started.md"),
    ),
    (
        "downloading-apps",
        "Downloading Apps",
        include_str!("../docs/downloading-apps.md"),
    ),
    (
        "membership",
        "Membership & Access",
        include_str!("../docs/membership.md"),
    ),
];

/// Minimal styling for the rendered markdown (bunyip-web has no Tailwind
/// typography plugin), scoped to `.docs-article`.
const DOCS_CSS: &str = "\
.docs-article{line-height:1.65;color:hsl(var(--foreground));}\
.docs-fill{background:hsl(var(--primary)/.15);color:hsl(var(--foreground));font-weight:600;padding:.05em .25em;border-radius:.2rem;}\
.docs-article h1,.docs-article h2,.docs-article h3{font-weight:600;line-height:1.25;margin:1.6em 0 .6em;}\
.docs-article h1{font-size:1.9rem;}.docs-article h2{font-size:1.45rem;}.docs-article h3{font-size:1.2rem;}\
.docs-article p,.docs-article ul,.docs-article ol{margin:.75em 0;}\
.docs-article ul,.docs-article ol{padding-left:1.5em;}.docs-article li{margin:.25em 0;}\
.docs-article a{color:hsl(var(--primary));text-decoration:underline;}\
.docs-article code{background:hsl(var(--muted));padding:.15em .35em;border-radius:.25rem;font-size:.9em;}\
.docs-article pre{background:hsl(var(--muted));padding:1em;border-radius:.5rem;overflow-x:auto;}\
.docs-article pre code{background:none;padding:0;}\
.docs-article table{border-collapse:collapse;margin:1em 0;display:block;overflow-x:auto;}\
.docs-article th,.docs-article td{border:1px solid hsl(var(--border));padding:.5em .75em;text-align:left;}\
.docs-article blockquote{border-left:3px solid hsl(var(--border));padding-left:1em;color:hsl(var(--muted-foreground));margin:1em 0;}\
";

fn render_markdown(md: &str) -> String {
    use pulldown_cmark::{html, Event, Options, Parser};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_TASKLISTS);
    // Defense-in-depth (BUNYIP-385 review): pulldown-cmark passes raw HTML in the
    // markdown through verbatim, and we splice the result with PreEscaped, so a
    // doc could otherwise inject live HTML into this public page. Drop the raw
    // Html / InlineHtml events; only markdown-derived HTML (which push_html
    // escapes correctly) is emitted. The embedded docs contain no raw HTML, so
    // this is lossless today.
    let events =
        Parser::new_ext(md, opts).filter(|ev| !matches!(ev, Event::Html(_) | Event::InlineHtml(_)));
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

/// Toggle for the personalized docs view. `?raw=1` forces the generic
/// (placeholder) rendering even when signed in.
#[derive(Debug, Default, Deserialize)]
pub struct DocQuery {
    #[serde(default)]
    raw: bool,
}

/// The escaped placeholder token, as it appears in `render_markdown` output
/// once pulldown-cmark has HTML-escaped the fenced `<username>` literal.
const USERNAME_TOKEN: &str = "&lt;username&gt;";

/// Replace the escaped `<username>` placeholder in already-rendered docs HTML
/// with the signed-in reader's own username (their Bunyip email, which is the
/// `docker login --username` value), highlighted. The email is HTML-escaped via
/// Maud before substitution so a crafted username cannot inject markup.
fn personalize_docs(html: &str, username: &str) -> String {
    let highlighted = maud::html! { span class="docs-fill" { (username) } }.into_string();
    html.replace(USERNAME_TOKEN, &highlighted)
}

/// `GET /docs` - index of the embedded docs. Public (BUNYIP-385).
pub async fn docs_index(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-4" { "Documentation" }
            p class="text-muted-foreground mb-8" { "Guides and runbooks for Mokosh and Bunyip. Temporary home while the dedicated docs app is built out." }
            ul class="space-y-3" {
                @for &(slug, title, _) in DOCS.iter() {
                    li {
                        a class="text-lg text-primary-text hover:underline" href=(format!("/docs/{slug}")) { (title) }
                    }
                }
            }
        }
    };
    public_response(&st, &c, &apps, &pricing, "Docs · Bunyip", true, content)
}

/// `GET /docs/{slug}` - render one embedded doc. Public (BUNYIP-385).
pub async fn docs_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(q): Query<DocQuery>,
) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let Some(&(_, title, md)) = DOCS.iter().find(|&&(s, _, _)| s == slug.as_str()) else {
        let content = html! {
            div class="container max-w-4xl py-12" {
                h1 class="text-4xl font-bold mb-4" { "Document not found" }
                p class="text-muted-foreground" {
                    "No such doc. " a class="text-primary-text hover:underline" href="/docs" { "Back to documentation" } "."
                }
            }
        };
        let mut resp = public_response(&st, &c, &apps, &pricing, "Docs · Bunyip", true, content);
        *resp.status_mut() = axum::http::StatusCode::NOT_FOUND;
        return resp;
    };
    let rendered = render_markdown(md);
    // Personalize only for a signed-in reader who has not opted into the raw
    // (generic) view, and only when the doc actually carries the placeholder.
    let username = c.user.as_ref().map(|u| u.email.as_str());
    let has_token = rendered.contains(USERNAME_TOKEN);
    let personalized = !q.raw && has_token && username.is_some();
    let body_html = if personalized {
        personalize_docs(&rendered, username.unwrap())
    } else {
        rendered
    };
    let content = html! {
        style { (PreEscaped(DOCS_CSS)) }
        div class="container max-w-4xl py-12" {
            div class="mb-6" { a class="text-sm text-primary-text hover:underline" href="/docs" { "← Documentation" } }
            @if has_token && username.is_some() {
                @if personalized {
                    p class="text-sm text-muted-foreground mb-6" {
                        "Personalized with your Bunyip username. "
                        a class="text-primary-text hover:underline" href=(format!("/docs/{slug}?raw=1")) { "Show the generic version" }
                    }
                } @else {
                    p class="text-sm text-muted-foreground mb-6" {
                        "Showing the generic version. "
                        a class="text-primary-text hover:underline" href=(format!("/docs/{slug}")) { "Personalize with your username" }
                    }
                }
            }
            article class="docs-article" { (PreEscaped(body_html)) }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        &format!("{title} · Docs · Bunyip"),
        true,
        content,
    )
}

/// `GET /apps/{slug}/docs` - an application's public documentation index
/// (BUNYIP-388). Pages come from the API; an app with none shows an empty state.
pub async fn app_docs_index(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let app_name = apps
        .iter()
        .find(|a| a.slug == slug)
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| slug.clone());
    let docs = calls::app_docs(&st.api, &slug).await.unwrap_or_default();
    let content = html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-4" { (app_name) " documentation" }
            @if docs.is_empty() {
                (empty_state("file-text", "Sorry. No docs for this app yet :(", None))
            } @else {
                ul class="space-y-3" {
                    @for d in &docs {
                        li {
                            a class="text-lg text-primary-text hover:underline" href=(format!("/apps/{slug}/docs/{}", d.slug)) { (d.title) }
                        }
                    }
                }
            }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        &format!("{app_name} docs · Bunyip"),
        true,
        content,
    )
}

/// `GET /apps/{slug}/docs/{doc_slug}` - render one app doc page. Public (BUNYIP-388).
pub async fn app_docs_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((slug, doc_slug)): Path<(String, String)>,
) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let app_name = apps
        .iter()
        .find(|a| a.slug == slug)
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| slug.clone());
    let doc = match calls::app_doc(&st.api, &slug, &doc_slug).await {
        Ok(d) => d,
        Err(_) => {
            let content = html! {
                div class="container max-w-4xl py-12" {
                    h1 class="text-4xl font-bold mb-4" { "Document not found" }
                    p class="text-muted-foreground" {
                        "No such page. "
                        a class="text-primary-text hover:underline" href=(format!("/apps/{slug}/docs")) { "Back to " (app_name) " docs" }
                        "."
                    }
                }
            };
            let mut resp =
                public_response(&st, &c, &apps, &pricing, "Docs · Bunyip", true, content);
            *resp.status_mut() = axum::http::StatusCode::NOT_FOUND;
            return resp;
        }
    };
    let content = html! {
        style { (PreEscaped(DOCS_CSS)) }
        div class="container max-w-4xl py-12" {
            div class="mb-6" {
                a class="text-sm text-muted-foreground hover:underline" href=(format!("/apps/{slug}/docs")) { "← " (app_name) " documentation" }
            }
            article class="docs-article" { (PreEscaped(render_markdown(&doc.body))) }
        }
    };
    public_response(
        &st,
        &c,
        &apps,
        &pricing,
        &format!("{} · {app_name} docs · Bunyip", doc.title),
        true,
        content,
    )
}

#[cfg(test)]
mod feedback_tests {
    use super::{feedback_form, read_feedback_multipart, sanitize_page_path};
    use axum::body::Body;
    use axum::extract::{FromRequest, Multipart};
    use axum::http::Request;

    const BOUNDARY: &str = "bunyip370boundary";

    /// Build a multipart body the way the browser posts the feedback form.
    fn multipart_body(fields: &[(&str, &str)]) -> String {
        let mut out = String::new();
        for (name, value) in fields {
            out.push_str(&format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ));
        }
        out.push_str(&format!("--{BOUNDARY}--\r\n"));
        out
    }

    async fn parse(fields: &[(&str, &str)]) -> super::FeedbackInput {
        let req = Request::builder()
            .method("POST")
            .uri("/feedback")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .body(Body::from(multipart_body(fields)))
            .expect("request builds");
        let mut multipart = Multipart::from_request(req, &())
            .await
            .expect("multipart extractor");
        read_feedback_multipart(&mut multipart)
            .await
            .expect("form parses")
    }

    /// BUNYIP-370: feedback opened from an admin screen submits through the
    /// same `/feedback` form and carries the admin path it came from, so an
    /// admin-originated report is captured through the existing path with its
    /// context intact.
    #[tokio::test]
    async fn admin_panel_submission_goes_through_the_existing_feedback_path() {
        let input = parse(&[
            ("name", "Ada"),
            ("email", "ada@example.com"),
            ("subject", "Users table"),
            ("message", "The tier filter drops the search term."),
            ("tags", "Bug"),
            ("page_path", "/admin/users"),
            ("website", ""),
        ])
        .await;

        assert_eq!(input.page_path, "/admin/users");
        assert_eq!(input.message, "The tier filter drops the search term.");
        assert_eq!(input.tags, vec!["Bug".to_string()]);
        assert_eq!(input.email, "ada@example.com");
    }

    /// The launcher's `?from=` value for an admin screen survives sanitization
    /// and round-trips into the hidden `page_path` input the POST reads back.
    #[test]
    fn admin_paths_round_trip_through_the_form() {
        for path in ["/admin", "/admin/users", "/admin/feedback?from=spam"] {
            let sanitized = sanitize_page_path(path).expect("admin path is accepted");
            assert_eq!(sanitized, path);
            let html = feedback_form(false, None, Some(&sanitized)).into_string();
            assert!(
                html.contains(&format!(r#"name="page_path" value="{path}""#)),
                "the hidden page_path input carries {path}"
            );
            assert!(
                html.contains(r#"action="/feedback""#),
                "the admin-originated form posts to the existing endpoint"
            );
        }
    }
}

#[cfg(test)]
mod pricing_tests {
    use super::{pricing_content, trial_phrase, PERSONAL};
    use crate::api::types::{PricingResponse, PricingTier, SubscriptionTier};

    fn standard(amount: i64, trial_days: i64) -> PricingResponse {
        PricingResponse {
            enabled: true,
            trial_days,
            tiers: vec![PricingTier {
                tier: SubscriptionTier::Standard,
                amount,
                currency: "usd".into(),
                interval: Some("month".into()),
                trial_days,
            }],
        }
    }

    /// BUNYIP-487: the advertised amount is whatever the mapped Stripe price
    /// says, so changing the mapping changes the page with no redeploy.
    #[test]
    fn amount_comes_from_the_resolved_stripe_price() {
        let html = pricing_content(&standard(300, 30), true, false).into_string();
        assert!(html.contains("$3.00"), "amount rendered from the price");
        assert!(!html.contains("$15"), "the hardcoded Business card is gone");

        let html = pricing_content(&standard(1250, 30), true, false).into_string();
        assert!(
            html.contains("$12.50"),
            "a different mapped price renders a different amount"
        );
    }

    /// The trial length comes from `tier_config.standard_trial_days`, so the
    /// page can no longer advertise a trial the application does not honour.
    #[test]
    fn trial_length_comes_from_config() {
        let html = pricing_content(&standard(300, 30), true, false).into_string();
        assert!(html.contains("free for 30 days"));
        let html = pricing_content(&standard(300, 7), true, false).into_string();
        assert!(html.contains("free for 7 days"));
        // Unknown length drops the number rather than inventing one.
        assert_eq!(trial_phrase(0), "free");
    }

    /// A pricing page that renders is a page with something to show: exactly
    /// the condition `published()` gates the route and every link on.
    #[test]
    fn unpublished_payloads_are_never_publishable() {
        let mut off = standard(300, 30);
        off.enabled = false;
        assert!(!off.published(), "switch off is not publishable");

        let mut empty = standard(300, 30);
        empty.tiers.clear();
        assert!(
            !empty.published(),
            "enabled with no resolvable price is not publishable"
        );
        assert!(standard(300, 30).published());
        assert!(!PricingResponse::default().published());
    }

    /// BUNYIP-487: the page must not advertise organizations.
    #[test]
    fn no_org_claims_in_the_rendered_page() {
        // Whole words, not substrings: class names and product names contain
        // "org" as a fragment.
        const BANNED_WORDS: &[&str] = &[
            "org",
            "orgs",
            "organisation",
            "organisations",
            "organization",
            "organizations",
            "teammate",
            "teammates",
        ];
        let html = pricing_content(&standard(300, 30), true, false)
            .into_string()
            .to_lowercase();
        for word in html.split(|c: char| !c.is_ascii_alphanumeric()) {
            assert!(
                !BANNED_WORDS.contains(&word),
                "the pricing page must not advertise {word:?}: it does not exist"
            );
        }
        assert!(
            !PERSONAL.iter().any(|f| f.to_lowercase().contains("org")),
            "feature bullets carry no org claim"
        );
    }
}

#[cfg(test)]
mod docs_tests {
    use super::{personalize_docs, render_markdown, DOCS, USERNAME_TOKEN};
    use std::collections::HashSet;

    #[test]
    fn docs_registry_is_sound() {
        assert!(!DOCS.is_empty());
        let mut seen = HashSet::new();
        for (slug, title, md) in DOCS {
            assert!(seen.insert(*slug), "duplicate doc slug: {slug}");
            assert!(!slug.is_empty() && !title.is_empty());
            assert!(md.len() > 20, "embedded doc {slug} looks empty");
        }
    }

    #[test]
    fn render_markdown_emits_html() {
        let html = render_markdown("# Title\n\nSome **bold** text.\n");
        assert!(html.contains("<h1>"), "heading not rendered");
        assert!(html.contains("<strong>bold</strong>"), "bold not rendered");
    }

    #[test]
    fn render_markdown_strips_raw_html() {
        // Block-level and inline raw HTML must be dropped, not emitted live.
        let html = render_markdown(
            "<script>alert(1)</script>\n\nHi <img src=x onerror=alert(1)> there.\n",
        );
        assert!(!html.contains("<script>"), "block raw HTML leaked");
        assert!(!html.contains("<img"), "inline raw HTML leaked");
        assert!(html.contains("Hi"), "surrounding text should survive");
    }

    #[test]
    fn downloading_apps_carries_username_placeholder() {
        // The personalization target: the rendered image-pull doc must contain
        // the escaped `<username>` token, or the substitution silently no-ops.
        let (_, _, md) = DOCS
            .iter()
            .find(|&&(s, _, _)| s == "downloading-apps")
            .expect("downloading-apps doc present");
        let html = render_markdown(md);
        assert!(
            html.contains(USERNAME_TOKEN),
            "rendered doc must contain the escaped <username> placeholder"
        );
    }

    #[test]
    fn personalize_docs_substitutes_and_highlights() {
        let html =
            render_markdown("```\ndocker login registry.example --username <username>\n```\n");
        assert!(html.contains(USERNAME_TOKEN));
        let out = personalize_docs(&html, "member@example.com");
        assert!(!out.contains(USERNAME_TOKEN), "placeholder should be gone");
        assert!(
            out.contains("<span class=\"docs-fill\">member@example.com</span>"),
            "username should be highlighted"
        );
    }

    #[test]
    fn personalize_docs_escapes_crafted_username() {
        // A crafted username must not inject markup into the public page.
        let html = render_markdown("```\ndocker login r --username <username>\n```\n");
        let out = personalize_docs(&html, "<script>alert(1)</script>");
        assert!(!out.contains("<script>"), "raw script tag injected");
        assert!(
            out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "crafted username should be HTML-escaped"
        );
    }
}
