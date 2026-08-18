//! Base document + page shells (public / dashboard / admin). Ported from the
//! Dioxus layouts. Theme is handled client-side by a tiny script (no reactive
//! framework): an early flash-prevention block + toggles that flip classes on
//! <html> and persist to the same `theme-storage` key.
//!
//! BUNYIP-424: every script this document loads is first-party and served from
//! `/assets` - no CDN, no inline `<script>` body, no `on*=` attribute - so
//! `crate::security` can ship `script-src 'self'`. Behaviour that used to live
//! in an inline block now lives in `assets/js/*.js` and is wired to the markup
//! through `data-*` attributes.

use std::sync::{Arc, OnceLock};

use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::api::types::{Application, Branding, User, UserRole};
use crate::config::Config;
use crate::util::app_link;
use crate::views::ui::{button_class, icon};

/// BUNYIP-145: the public-facing origin of bunyip-api the browser's
/// `EventSource` connects to. Set once at startup from `Config::api_url`;
/// read by every authenticated shell so the dashboard / admin pages can
/// open a long-lived SSE stream without threading the config through 45
/// handler call sites.
static SSE_API_ORIGIN: OnceLock<String> = OnceLock::new();

/// BUNYIP-145: install the public-facing bunyip-api origin used by the SSE
/// subscriber injected into the dashboard / admin shells. Called once from
/// `main` before any request is served. Idempotent (the underlying
/// `OnceLock` ignores subsequent sets).
pub fn install_sse_api_origin(origin: impl Into<String>) {
    let _ = SSE_API_ORIGIN.set(origin.into().trim_end_matches('/').to_string());
}

/// BUNYIP-554: the build-derived cache buster every `/assets/*` reference
/// carries. `main.rs` serves that directory with `max-age=31536000, immutable`,
/// so the query string is the only thing that lets a deploy reach a warm cache;
/// without it the year-long lifetime would pin the old bytes. Set by
/// `build.rs` from the short commit (or the build timestamp when git is absent).
pub fn asset_version() -> &'static str {
    env!("ASSET_VERSION")
}

/// A versioned `/assets/*` URL. Every reference in the markup goes through
/// this - an unversioned one is served `immutable` and can never be updated.
pub fn asset(path: &str) -> String {
    format!("{path}?v={}", asset_version())
}

fn sse_api_origin() -> &'static str {
    SSE_API_ORIGIN
        .get()
        .map(String::as_str)
        .unwrap_or("http://localhost:4401")
}

/// BUNYIP-329: whether the Community (Let's Chat) nav entry is shown. Set once
/// from `main` out of `Config::community_enabled()`, so the sidebar can gate
/// the item without threading config through every `dashboard_response` caller
/// (same pattern as [`SSE_API_ORIGIN`]).
static COMMUNITY_ENABLED: OnceLock<bool> = OnceLock::new();

/// Install the Community feature flag. Called once from `main` before serving.
/// Idempotent (the underlying `OnceLock` ignores subsequent sets).
pub fn install_community_enabled(enabled: bool) {
    let _ = COMMUNITY_ENABLED.set(enabled);
}

fn community_enabled() -> bool {
    *COMMUNITY_ENABLED.get().unwrap_or(&false)
}

/// BUNYIP-500: optional per-skin theme override (raw CSS custom-property
/// declarations for the brand ramp, `Config::theme_css`). Set once from `main`
/// (same `OnceLock` pattern as [`SSE_API_ORIGIN`]); emitted into a `:root`
/// block in the document head. Unset (the default) emits nothing, so the
/// `@theme` tokens fall back to the default palette.
static SKIN_THEME_CSS: OnceLock<Option<String>> = OnceLock::new();

/// Install the per-skin theme override. Called once from `main` before serving.
/// Idempotent (the underlying `OnceLock` ignores subsequent sets).
pub fn install_skin_theme_css(css: Option<String>) {
    let _ = SKIN_THEME_CSS.set(css);
}

fn skin_theme_css() -> Option<&'static str> {
    SKIN_THEME_CSS.get().and_then(Option::as_deref)
}

/// BUNYIP-549: the two `<meta name="theme-color">` values (light scheme, dark
/// scheme) that paint the browser chrome. A skin recolours every in-page token
/// through [`SKIN_THEME_CSS`], so the chrome colour is config-supplied too
/// (`Config::theme_color_light` / `theme_color_dark`) rather than a literal in
/// this shell. Set once from `main` (same `OnceLock` pattern as
/// [`SSE_API_ORIGIN`]); unset falls back to the bunyip defaults in
/// `crate::config`, so unskinned output is byte-identical.
static THEME_COLOR_LIGHT: OnceLock<String> = OnceLock::new();
static THEME_COLOR_DARK: OnceLock<String> = OnceLock::new();

/// Install the browser-chrome colours. Called once from `main` before serving.
/// Idempotent (the underlying `OnceLock`s ignore subsequent sets).
pub fn install_theme_colors(light: impl Into<String>, dark: impl Into<String>) {
    let _ = THEME_COLOR_LIGHT.set(light.into());
    let _ = THEME_COLOR_DARK.set(dark.into());
}

fn theme_color_light() -> &'static str {
    THEME_COLOR_LIGHT
        .get()
        .map(String::as_str)
        .unwrap_or(crate::config::DEFAULT_THEME_COLOR_LIGHT)
}

fn theme_color_dark() -> &'static str {
    THEME_COLOR_DARK
        .get()
        .map(String::as_str)
        .unwrap_or(crate::config::DEFAULT_THEME_COLOR_DARK)
}

/// BUNYIP-561: the admin-managed branding record (product name, tagline, meta
/// description, Open Graph image), fetched from bunyip-api and refreshed on an
/// interval by [`crate::branding`]. It replaced the `APP_NAME` /
/// `BRAND_DESCRIPTION` `OnceLock`s and their compiled-in fallback literals: an
/// empty field here omits its markup, and no copy is ever substituted.
pub fn branding() -> Arc<Branding> {
    crate::branding::current()
}

/// The product name for the nav mark, the browser-title suffix and
/// `og:site_name`. Empty when nothing has been branded and nothing has loaded,
/// in which case every site that renders it omits it.
pub fn brand_name() -> String {
    branding().brand_name.clone()
}

/// BUNYIP-145 / BUNYIP-424: the browser-facing origin the dashboard's
/// `EventSource` connects to, handed to `assets/js/sse.js` as a `data-` attribute
/// on its own `<script>` tag. Server values reach the client as passive markup,
/// never as executable JavaScript.
fn sse_subscriber_script() -> Markup {
    html! {
        script src=(asset("/assets/js/sse.js")) data-api-origin=(sse_api_origin()) defer {}
    }
}

/// BUNYIP-561: the browser-title string, `"<page> · <brand>"`, or the bare page
/// title when nothing has been branded. Also what `og:title` carries, so the
/// two never disagree. Pure, so the omission rule is unit-testable.
fn document_title(page_title: &str, branding: &Branding) -> String {
    if branding.brand_name.is_empty() {
        page_title.to_string()
    } else {
        format!("{page_title} · {}", branding.brand_name)
    }
}

/// BUNYIP-561: the sharing metadata. Every tag is omitted when its source value
/// is empty, so an unbranded deployment emits none of them rather than
/// advertising a placeholder. There is deliberately no `og:url`: `document()`
/// has no request context, and a wrong canonical URL is worse than none.
///
/// `twitter:card` is `summary_large_image` only when an image URL is set;
/// without one the large-image card renders as a blank rectangle.
fn social_meta(page_title: &str, branding: &Branding) -> Markup {
    let has_any = !branding.brand_name.is_empty()
        || !branding.meta_description.is_empty()
        || !branding.og_image_url.is_empty();
    html! {
        @if has_any {
            meta property="og:type" content="website";
            meta name="twitter:card" content=(if branding.og_image_url.is_empty() { "summary" } else { "summary_large_image" });
            meta property="og:title" content=(document_title(page_title, branding));
            meta name="twitter:title" content=(document_title(page_title, branding));
        }
        @if !branding.brand_name.is_empty() {
            meta property="og:site_name" content=(branding.brand_name);
        }
        @if !branding.meta_description.is_empty() {
            meta property="og:description" content=(branding.meta_description);
            meta name="twitter:description" content=(branding.meta_description);
        }
        @if !branding.og_image_url.is_empty() {
            meta property="og:image" content=(branding.og_image_url);
            meta name="twitter:image" content=(branding.og_image_url);
        }
    }
}

pub fn document(title: &str, body: Markup) -> Markup {
    document_with_avatar_picker(title, body, false)
}

/// BUNYIP-554: `document()` plus the avatar picker's stylesheet and controller.
/// The picker renders on exactly one page (`/settings`), so the shared shell
/// carries only `AVATAR_SLOT_CSS` - the one rule its avatar image needs - and
/// the remaining rules plus `avatar-picker.js` ship on that page alone.
/// Reached through `handlers::dashboard_response_with_avatar_picker`.
pub fn document_with_avatar_picker(title: &str, body: Markup, with_avatar_picker: bool) -> Markup {
    let branding = branding();
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                // BUNYIP-561: omitted, not defaulted, when the admin has set no
                // description. A compiled-in sentence here is exactly the copy
                // this issue took out of the binary.
                @if !branding.meta_description.is_empty() {
                    meta name="description" content=(branding.meta_description);
                }
                meta name="theme-color" media="(prefers-color-scheme: light)" content=(theme_color_light());
                meta name="theme-color" media="(prefers-color-scheme: dark)" content=(theme_color_dark());
                (social_meta(title, &branding))
                title { (document_title(title, &branding)) }
                // BUNYIP-339: favicon set derived from the hero art (face crop,
                // rounded corners). Served from /assets via ServeDir.
                link rel="icon" href=(asset("/assets/favicon.ico")) sizes="any";
                link rel="icon" type="image/png" sizes="16x16" href=(asset("/assets/favicon-16x16.png"));
                link rel="icon" type="image/png" sizes="32x32" href=(asset("/assets/favicon-32x32.png"));
                link rel="icon" type="image/png" sizes="48x48" href=(asset("/assets/favicon-48x48.png"));
                link rel="icon" type="image/png" sizes="192x192" href=(asset("/assets/favicon-192x192.png"));
                // BUNYIP-554: the 512 icon is WebP. The artwork is a dense
                // illustration, and PNG cannot encode it under the 30 KB budget
                // without destroying it (measured: 30,723 bytes only at blur 3.0
                // and 16 colours); WebP holds it at 28,228. Browsers that do not
                // decode WebP skip the candidate and fall back to the 192 PNG.
                link rel="icon" type="image/webp" sizes="512x512" href=(asset("/assets/favicon-512x512.webp"));
                // apple-touch-icon stays PNG: iOS home-screen icons are not
                // fetched as WebP.
                link rel="apple-touch-icon" sizes="180x180" href=(asset("/assets/apple-touch-icon.png"));
                link rel="stylesheet" href=(asset("/assets/styles.css"));
                // BUNYIP-500: per-skin theme override. The brand `@theme` tokens
                // read `var(--skin-*, <default>)`, so a skin recolors the UI by
                // setting `--skin-*` here. Config-supplied (trusted), and CSP
                // already allows `style-src 'unsafe-inline'`. Unset -> no block ->
                // the default palette.
                @if let Some(css) = skin_theme_css() {
                    style { ":root{" (PreEscaped(css)) "}" }
                }
                // BUNYIP-294: `defer` so no script blocks HTML parsing. A
                // render-blocking `<script src>` in `<head>` gated page-ready
                // timing on network latency, which raced the automated credential
                // fill on chromium CI - the `/login` form was not settled when
                // typed into, so the submit POSTed empty and the hub re-rendered
                // the form (mokosh PMS-605). `defer` preserves execution order and
                // runs after parse, before DOMContentLoaded.
                //
                // BUNYIP-424: htmx is vendored (byte-identical to the published
                // htmx 2.0.3 dist, sha384-0895/pl2MU10Hqc6jd4RvrthNlDiE9U1tWmX7WRESftEDRosgxNsQG/Ze9YMRzHq)
                // instead of pulled from unpkg, which resolves from npm at request
                // time and so is replaceable by an upstream account compromise.
                script src=(asset("/assets/vendor/htmx-2.0.3.min.js")) defer {}
                // theme.js is NOT deferred: the stored theme has to land on
                // <html> before first paint or the page flashes the wrong theme.
                script src=(asset("/assets/js/theme.js")) {}
                script src=(asset("/assets/js/app.js")) defer {}
                // BUNYIP-473: drag-and-drop / keyboard reordering for admin
                // lists. Inert on pages without a `[data-reorder-list]`.
                script src=(asset("/assets/js/app-reorder.js")) defer {}
                // BUNYIP-408: avatar CSS shipped inline (not via the separately
                // cached styles.css) so a stale stylesheet can never leave the
                // component's structural rules undefined. BUNYIP-554: only the
                // slot rule is shared; the picker's own rules and controller
                // ship on the one page that renders it.
                style { (PreEscaped(crate::views::avatar_picker::AVATAR_SLOT_CSS)) }
                @if with_avatar_picker {
                    style { (PreEscaped(crate::views::avatar_picker::AVATAR_PICKER_CSS)) }
                    script src=(asset("/assets/js/avatar-picker.js")) defer {}
                }
            }
            body {
                // BUNYIP-243: app-wide "service unavailable" banner. Renders
                // nothing while bunyip-api is reachable; when down it shows on
                // every page (including /login) so an outage is communicated
                // instead of reading as a phantom logout or silently empty page.
                (crate::server_status::banner())
                (body)
                // Toast surface: lives at top-right with pointer-events:none
                // on the container and pointer-events:auto on each pill, so
                // dismissed regions never block clicks. polite + atomic so
                // screen readers announce each message in full.
                div id="bunyip-toast-root"
                    class="pointer-events-none fixed top-4 right-4 z-50 flex flex-col gap-2"
                    aria-live="polite" aria-atomic="true" {}
            }
        }
    }
}

/// Reed-and-eyes brand mark, ported from the Dioxus `BrandMark` component.
fn brand_mark() -> Markup {
    html! {
        svg class="w-7 h-7 text-brand-primary-700 dark:text-brand-primary-200" viewBox="0 0 32 32" fill="none" {
            path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M8 28 V14 M16 28 V8 M24 28 V14" {}
            circle cx="12.5" cy="18" r="2" fill="currentColor" {}
            circle cx="19.5" cy="18" r="2" fill="currentColor" {}
        }
    }
}

fn brand() -> Markup {
    html! {
        a href="/" class="flex items-center gap-2 group" {
            (brand_mark())
            span class="text-2xl font-semibold tracking-tight text-brand-primary-900 dark:text-brand-primary-50 group-hover:text-brand-primary-700 dark:group-hover:text-brand-primary-200 transition-colors" { (brand_name()) }
        }
    }
}

fn theme_controls(icon_class: &str) -> Markup {
    html! {
        // BUNYIP-424: `data-theme-toggle` / `data-contrast-toggle` replace the
        // old inline click handlers; `assets/js/theme.js` binds them.
        button type="button" aria-label="Toggle theme" class=(button_class("ghost", "icon", "")) data-theme-toggle {
            span class="rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" { (icon("sun", icon_class)) }
            span class="absolute rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" { (icon("moon", icon_class)) }
        }
        button type="button" aria-label="Toggle high contrast" class=(button_class("ghost", "icon", "")) data-contrast-toggle {
            (icon("contrast", icon_class))
        }
    }
}

/// Floating "open feedback" launcher pinned to the bottom-right of the
/// viewport. BUNYIP-370: mounted by EVERY authenticated shell -
/// `dashboard_shell` and `admin_shell` - so feedback can be sent from any
/// app surface, not just the user dashboard. `public_shell` mounts it too,
/// gated by `show_feedback` (kept off on the login / register / consent flow,
/// where the chrome is deliberately minimal, and off on `/feedback` itself).
/// Pages whose primary action lands in the
/// bottom-right (currently `/downloads`) add their own `pb-24` so the
/// launcher does not occlude content; see the wrapper in the Downloads
/// handler.
///
/// The link carries the originating page to the feedback form via a `?from=`
/// query param. It is set client-side by `assets/js/app.js` (keyed on
/// `data-feedback-link`) from `location.pathname + location.search` - the
/// launcher is shared by all shells and has no server-side access to the
/// request path; threading it through every shell + response helper + handler
/// call site would be far more invasive. The static `href="/feedback"` remains
/// a no-JS fallback. The
/// `/feedback` GET handler reads `?from=`, sanitizes it (must start with `/`),
/// and round-trips it into the hidden `page_path` input.
fn feedback_launcher() -> Markup {
    html! {
        div class="pointer-events-none fixed bottom-4 right-4 z-40 sm:bottom-6 sm:right-6" {
            a href="/feedback" aria-label="Open feedback page" data-feedback-link
              class="pointer-events-auto group flex h-14 w-[60px] items-center overflow-hidden rounded-2xl border border-border/70 bg-background/85 text-primary-text shadow-xl shadow-primary/10 backdrop-blur-md transition-all duration-300 hover:w-[204px] hover:border-primary/50 hover:bg-background dark:bg-card/90 sm:h-16 sm:w-16 sm:hover:w-[214px]" {
                span class="relative inline-flex h-14 w-[60px] shrink-0 items-center justify-center rounded-2xl sm:h-16 sm:w-16" {
                    span class="absolute inset-0 rounded-2xl bg-gradient-to-br from-primary/18 via-indigo-500/12 to-teal-500/18 opacity-80" {}
                    (icon("smile-plus", "feedback-launcher__icon-bounce relative z-10 h-7 w-7 sm:h-8 sm:w-8"))
                }
                span class="max-w-0 whitespace-nowrap pl-0 pr-0 text-sm font-medium text-foreground opacity-0 transition-all duration-300 group-hover:max-w-[130px] group-hover:pl-4 group-hover:pr-4 group-hover:opacity-100" { "Have feedback?" }
            }
        }
    }
}

/// `_show_feedback` is the public-shell flag that gates whether the floating
/// launcher is mounted; the header itself no longer renders any feedback
/// affordance (the launcher lives below the page content, mounted by the
/// shell). Parameter is kept so call sites do not change; the underscore
/// silences the unused-arg lint.
fn header(user: Option<&User>, pricing: bool, _show_feedback: bool) -> Markup {
    let is_admin = user.map(|u| u.role == UserRole::Admin).unwrap_or(false);
    html! {
        header class="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60" {
            div class="container flex h-16 items-center justify-between" {
                div class="flex items-center gap-6" {
                    (brand())
                    nav class="hidden md:flex items-center gap-6" {
                        // BUNYIP-487: /pricing 404s unless an admin enabled it
                        // and a tier resolves to a Stripe price, so the link
                        // exists only when the page does.
                        @if pricing { a href="/pricing" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Pricing" } }
                        a href="/our-story" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Our Story" }
                        a href="/roadmap" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Roadmap" }
                    }
                }
                div class="flex items-center gap-4" {
                    (theme_controls("h-5 w-5"))
                    @if let Some(u) = user {
                        a href="/dashboard" class=(button_class("ghost", "sm", "")) { "Dashboard" }
                        @if is_admin { a href="/admin" class=(button_class("ghost", "sm", "")) { "Admin" } }
                        // BUNYIP-408: same profile menu as the app shells, so the
                        // documentation / marketing pages reach profile + logout
                        // through the identical affordance.
                        (profile_menu(u))
                    } @else {
                        a href="/register" class=(button_class("default", "sm", "")) { "Sign up" }
                        a href="/login" class=(button_class("outline", "sm", "")) { "Sign in" }
                    }
                }
            }
        }
    }
}

fn footer(cfg: &Config, apps: &[Application], pricing: bool) -> Markup {
    let year = chrono::Utc::now().format("%Y").to_string();
    html! {
        footer class="border-t border-border/50 bg-gradient-to-b from-background to-indigo-950/5 dark:to-indigo-950/30" {
            div class="container py-8 md:py-12" {
                div class="grid grid-cols-2 gap-8 md:grid-cols-4" {
                    div class="col-span-2 md:col-span-1" {
                        (brand())
                        // BUNYIP-561: the tagline is the admin-managed record,
                        // omitted entirely when unset rather than replaced by a
                        // compiled-in line.
                        @if !branding().tagline.is_empty() {
                            p class="mt-4 text-sm text-muted-foreground" { (branding().tagline) }
                        }
                        p class="mt-1 text-xs text-muted-foreground" { (brand_name()) " · " (cfg.domain_or_localhost()) }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Product" }
                        ul class="mt-4 space-y-3 text-sm" {
                            @if pricing { li { a href="/pricing" class="text-muted-foreground hover:text-foreground transition-colors" { "Pricing" } } }
                            li { a href="/our-story" class="text-muted-foreground hover:text-foreground transition-colors" { "Our Story" } }
                            li { a href="/roadmap" class="text-muted-foreground hover:text-foreground transition-colors" { "Roadmap" } }
                            @for app in apps {
                                li { a href=(app_link(app, &cfg.app_domain)) class="text-muted-foreground hover:text-foreground transition-colors" { (app.display_name) } }
                            }
                        }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Account" }
                        ul class="mt-4 space-y-3 text-sm" {
                            li { a href="/login" class="text-muted-foreground hover:text-foreground transition-colors" { "Sign in" } }
                            li { a href="/register" class="text-muted-foreground hover:text-foreground transition-colors" { "Sign up" } }
                        }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Legal" }
                        ul class="mt-4 space-y-3 text-sm" {
                            li { a href="/terms" class="text-muted-foreground hover:text-foreground transition-colors" { "Terms of Service" } }
                            li { a href="/privacy" class="text-muted-foreground hover:text-foreground transition-colors" { "Privacy Policy" } }
                        }
                    }
                }
                div class="mt-8 border-t border-border/50 pt-8 text-center text-sm text-muted-foreground" {
                    p { "© " (year) " " (cfg.domain_or_localhost()) ". All rights reserved." }
                }
            }
        }
    }
}

/// `show_feedback` mirrors the historical `launcher: bool` parameter (the name
/// changed when the floating widget was retired; the semantic stays the same).
/// `true` for the marketing pages (Pricing / Our Story / Terms / Privacy);
/// `false` for the login / register flow where the chrome is intentionally
/// minimal. The flag is plumbed into `header()` so the top-bar button (and
/// nothing else) honours it.
pub fn public_shell(
    cfg: &Config,
    user: Option<&User>,
    apps: &[Application],
    pricing: bool,
    show_feedback: bool,
    content: Markup,
) -> Markup {
    html! {
        div class="flex min-h-screen flex-col" {
            (header(user, pricing, show_feedback))
            main class="flex-1" { (content) }
            (footer(cfg, apps, pricing))
            @if show_feedback { (feedback_launcher()) }
        }
    }
}

struct NavItem {
    title: &'static str,
    href: &'static str,
    icon: &'static str,
}

fn dashboard_items(is_member: bool) -> Vec<NavItem> {
    let mut items = vec![NavItem {
        title: "Dashboard",
        href: "/dashboard",
        icon: "layout-dashboard",
    }];
    // BUNYIP-329: Community (Let's Chat) sits high in the nav so it is front
    // and centre, but only for members and only when an instance is configured
    // (the `/community` route otherwise has nowhere to send them).
    if is_member && community_enabled() {
        items.push(NavItem {
            title: "Community",
            href: "/community",
            icon: "message-square-quote",
        });
    }
    items.extend([
        NavItem {
            title: "Applications",
            href: "/applications",
            icon: "app-window",
        },
        // Downloads moved onto each application card (BUNYIP-100); the
        // standalone /downloads page is now a redirect to /applications.
        // Single nav entry covering plan, status, invoices, and payment
        // history. The standalone "Billing" item went away when /billing
        // became a 302 redirect into /membership. See
        // docs/bunyip-upgrade/01-membership-plan-data.md.
        NavItem {
            title: "Membership & Billing",
            href: "/membership",
            icon: "credit-card",
        },
        NavItem {
            title: "Settings",
            href: "/settings",
            icon: "settings",
        },
    ]);
    items
}

fn admin_items() -> Vec<NavItem> {
    vec![
        NavItem {
            title: "Admin Dashboard",
            href: "/admin",
            icon: "layout-dashboard",
        },
        // BUNYIP-410: Memberships folded into the Users page (tier column +
        // filter bar); its nav entry is removed and /admin/memberships redirects
        // to the filtered users list.
        NavItem {
            title: "Users",
            href: "/admin/users",
            icon: "users",
        },
        NavItem {
            title: "Applications",
            href: "/admin/applications",
            icon: "app-window",
        },
        NavItem {
            title: "Application Groups",
            href: "/admin/application-groups",
            icon: "layers",
        },
        NavItem {
            title: "Entitlements",
            href: "/admin/entitlements",
            icon: "key",
        },
        // BUNYIP-561: the product name, tagline, meta description and Open
        // Graph image, so a rebrand is an admin edit rather than a redeploy.
        NavItem {
            title: "Branding",
            href: "/admin/branding",
            // `views::ui::icon` renders an empty glyph for a name it does not
            // know, so this stays inside the existing set (BUNYIP-560 brings
            // the brand assets, and their icon, with it).
            icon: "globe",
        },
        NavItem {
            title: "Email",
            href: "/admin/email",
            icon: "mail",
        },
        NavItem {
            title: "Stripe",
            href: "/admin/stripe",
            icon: "banknote",
        },
        NavItem {
            // BUNYIP-487: label only. The route stays /admin/tier-settings so
            // existing admin bookmarks keep working.
            title: "Pricing Tiers",
            href: "/admin/tier-settings",
            icon: "settings",
        },
        NavItem {
            title: "Feedback",
            href: "/admin/feedback",
            icon: "message-square-quote",
        },
        NavItem {
            title: "Audit Logs",
            href: "/admin/audit-logs",
            icon: "file-text",
        },
        NavItem {
            title: "Error Logs",
            href: "/admin/logs",
            icon: "alert-triangle",
        },
        NavItem {
            title: "Seed Data",
            href: "/admin/seed",
            icon: "layers",
        },
        NavItem {
            title: "IP Bans",
            href: "/admin/ip-bans",
            icon: "shield-off",
        },
        NavItem {
            title: "Auto-ban Settings",
            href: "/admin/auto-ban-settings",
            icon: "shield-alert",
        },
        NavItem {
            title: "Rate Limits",
            href: "/admin/rate-limits",
            icon: "gauge",
        },
    ]
}

const NAV_ACTIVE: &str =
    "bg-gradient-to-r from-primary to-indigo-500 text-white shadow-md shadow-primary/20";
const NAV_INACTIVE: &str = "text-muted-foreground hover:bg-accent hover:text-accent-foreground";

/// BUNYIP-547: the complete nav destination list of an authenticated shell,
/// grouped into the sections a divider separates. The cross-shell switch
/// (BUNYIP-417) is its own leading section; the page items follow. Both the
/// sidebar and the below-`md` disclosure render from this one list, so an entry
/// added here reaches every width.
fn shell_nav_sections(admin: bool, is_admin: bool, is_member: bool) -> Vec<Vec<NavItem>> {
    let mut sections = Vec::new();
    // BUNYIP-417: the user/admin dashboard switch is a top-level, frequently
    // used control, so it sits at the TOP of the nav rather than at the bottom.
    if admin {
        sections.push(vec![NavItem {
            title: "User Dashboard",
            href: "/dashboard",
            icon: "layout-dashboard",
        }]);
    } else if is_admin {
        sections.push(vec![NavItem {
            title: "Admin Panel",
            href: "/admin",
            icon: "shield",
        }]);
    }
    sections.push(if admin {
        admin_items()
    } else {
        dashboard_items(is_member)
    });
    sections
}

/// The nav rows themselves, shared by the sidebar and the below-`md` disclosure
/// (BUNYIP-547) so the two cannot drift in destinations, active styling, or
/// external-link handling.
fn nav_links(sections: &[Vec<NavItem>], active: &str) -> Markup {
    html! {
        @for (i, section) in sections.iter().enumerate() {
            @if i > 0 { div class="my-3 border-t border-border/50" {} }
            @for item in section {
                // BUNYIP-329: Community launches the external Let's Chat
                // instance, so open it in a new tab and keep this one.
                @let external = item.href == "/community";
                a href=(item.href)
                  target=[external.then_some("_blank")]
                  rel=[external.then_some("noopener noreferrer")]
                  class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all " (if active == item.href { NAV_ACTIVE } else { NAV_INACTIVE }) } {
                    (icon(item.icon, "h-4 w-4"))
                    (item.title)
                    // BUNYIP-341: flag the external Community launch with a
                    // trailing external-link glyph (opens in a new tab), so
                    // the row reads as "leaves this app" before it is clicked.
                    @if external {
                        (icon("external-link", "ml-auto h-3.5 w-3.5 opacity-60"))
                    }
                }
            }
        }
    }
}

/// BUNYIP-547: the authenticated navigation below the `md` breakpoint, where
/// [`sidebar`] is not rendered at all. A `<details data-menu>` disclosure, the
/// same pattern [`profile_menu`] uses, so it inherits the click-away and Escape
/// dismissal already bound in `assets/js/app.js` and needs no new script. Its
/// panel scrolls (`overflow-y-auto`) because the admin list is fifteen entries.
fn mobile_nav(admin: bool, is_admin: bool, active: &str, is_member: bool) -> Markup {
    let sections = shell_nav_sections(admin, is_admin, is_member);
    html! {
        details class="relative md:hidden" data-menu data-mobile-nav {
            summary class="flex h-9 w-9 cursor-pointer list-none items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground [&::-webkit-details-marker]:hidden"
                    aria-label="Open navigation" {
                (icon("menu", "h-5 w-5"))
            }
            nav class="absolute left-0 z-50 mt-2 max-h-[70vh] w-64 space-y-1 overflow-y-auto rounded-md border border-border/60 bg-background p-2 shadow-lg" {
                (nav_links(&sections, active))
            }
        }
    }
}

fn sidebar(admin: bool, is_admin: bool, active: &str, is_member: bool) -> Markup {
    let sections = shell_nav_sections(admin, is_admin, is_member);
    html! {
        // BUNYIP-368: the sidebar is its own scroll container. It fills the
        // viewport-locked shell (`h-full`), keeps the brand row pinned
        // (`shrink-0`), and scrolls only the nav, so a long nav never drags the
        // page body with it. `shrink-0` on the column holds the w-64 width.
        aside class="hidden md:flex h-full w-64 shrink-0 flex-col overflow-hidden border-r border-border/50 bg-gradient-to-b from-background via-background to-indigo-950/5 dark:to-indigo-950/20" {
            div class="flex h-16 shrink-0 items-center border-b border-border/50 px-6" {
                (brand())
                @if admin {
                    span class="ml-2 rounded bg-gradient-to-r from-indigo-500/20 to-teal-500/20 px-2 py-0.5 text-xs font-medium text-indigo-600 dark:text-indigo-400" { "Admin" }
                }
            }
            nav class="flex-1 space-y-1 overflow-y-auto p-4" {
                (nav_links(&sections, active))
            }
        }
    }
}

/// BUNYIP-408: the round avatar shown in the profile menu. Renders the uploaded
/// image when the user has one; otherwise a gradient circle with the display
/// name's initial. `size` supplies the Tailwind sizing classes (e.g. `h-8 w-8`).
fn avatar_badge(user: &User, size: &str) -> Markup {
    let src = user.avatar_src();
    let has = src.is_some();
    html! {
        // `data-avatar-slot` marks this as an avatar surface the picker's
        // controller repaints after an upload/removal (BUNYIP-408), so the
        // header menu updates without a full-page reload. The image and the
        // letter fallback are both wired via `data-avatar-image` /
        // `data-avatar-initial`; the JS toggles between them.
        span class={ "relative inline-flex items-center justify-center overflow-hidden rounded-full border border-border/60 " (size) }
             data-avatar-slot data-initial=(user.avatar_initial()) {
            @if let Some(s) = &src {
                img src=(s) alt="Profile photo" class="avatar-slot__img" data-avatar-image;
            }
            span data-avatar-initial aria-hidden="true"
                 class="inline-flex h-full w-full items-center justify-center rounded-full bg-gradient-to-br from-primary to-indigo-500 text-white text-sm font-semibold"
                 style=[has.then_some("display:none")] {
                (user.avatar_initial())
            }
        }
    }
}

/// BUNYIP-408: the consistent upper-right profile menu shared by every shell
/// (dashboard, admin, and the public header). An avatar button opens a dropdown
/// containing a link to profile settings and Log out - replacing the old
/// standalone logout link + raw-email display. Built on `<details>`/`<summary>`
/// so it is keyboard-accessible without a framework; `assets/js/app.js` adds
/// click-away / Escape dismissal.
fn profile_menu(user: &User) -> Markup {
    html! {
        details class="relative" data-menu {
            summary class="flex items-center gap-2 cursor-pointer list-none rounded-full py-1 pl-1 pr-2 hover:bg-accent transition-colors [&::-webkit-details-marker]:hidden" {
                (avatar_badge(user, "h-8 w-8"))
                span class="hidden text-sm font-medium text-foreground sm:inline" { (user.display_name()) }
                (icon("chevron-down", "h-4 w-4 text-muted-foreground"))
            }
            div class="absolute right-0 z-50 mt-2 w-56 overflow-hidden rounded-md border border-border/60 bg-background py-1 shadow-lg" {
                div class="border-b border-border/60 px-3 py-2" {
                    p class="truncate text-sm font-medium text-foreground" { (user.display_name()) }
                    p class="truncate text-xs text-muted-foreground" { (user.email) }
                }
                a href="/settings" class="flex items-center gap-2 px-3 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors" {
                    (icon("user", "h-4 w-4")) "Profile"
                }
                a href="/logout" class="flex items-center gap-2 px-3 py-2 text-sm text-destructive-text hover:bg-accent transition-colors" {
                    (icon("log-out", "h-4 w-4")) "Log out"
                }
            }
        }
    }
}

/// `nav` is the below-`md` navigation disclosure ([`mobile_nav`]), rendered left
/// of the page title. It is the only nav an authenticated shell has under 768px,
/// where [`sidebar`] is `hidden` (BUNYIP-547).
fn app_topbar(title: &str, user: &User, nav: Markup) -> Markup {
    html! {
        // BUNYIP-408: `relative z-40` gives the topbar a stacking context that
        // sits above the scrolling `<main>` content. Without it the profile-menu
        // dropdown (which overflows below the h-16 bar) is painted OVER by the
        // page's cards, so it looked cut off and its rows were neither hoverable
        // nor clickable in the dashboard / admin shells. The public `header`
        // already carries `z-50`, which is why the same component worked there.
        header class="relative z-40 flex h-16 items-center justify-between border-b border-border/50 bg-background/80 backdrop-blur-sm px-6" {
            div class="flex min-w-0 items-center gap-2" {
                (nav)
                h1 class="truncate text-lg font-semibold" { (title) }
            }
            div class="flex items-center gap-2" {
                (theme_controls("h-4 w-4"))
                (profile_menu(user))
            }
        }
    }
}

/// BUNYIP-368: the authenticated shells pin themselves to the viewport from the
/// `md` breakpoint up (the breakpoint at which the sidebar is rendered at all),
/// so the sidebar and `<main>` are each their own scroll container and neither
/// drags the document with it. Below `md` there is no sidebar, so the page keeps
/// its natural full-document scroll (`min-h-screen`).
const APP_SHELL_CLASS: &str = "flex min-h-screen md:h-screen md:overflow-hidden";
/// The content column next to the sidebar: the topbar stays put and only
/// `<main>` inside it scrolls.
const APP_COLUMN_CLASS: &str = "flex flex-1 flex-col overflow-hidden";
const APP_MAIN_CLASS: &str = "relative flex-1 overflow-y-auto p-6";

/// `topbar_title` is the heading rendered in the top bar (NOT the browser
/// `<title>`). BUNYIP-499: it is the bare page title; the browser tab's
/// " · {app_name}" suffix is appended separately in `document()`, so the header
/// and the tab title no longer diverge by a hardcoded brand string.
pub fn dashboard_shell(user: &User, active: &str, topbar_title: &str, content: Markup) -> Markup {
    let is_admin = user.role == UserRole::Admin;
    let is_member = crate::util::has_active_membership(Some(user));
    let sse = sse_subscriber_script();
    html! {
        div class=(APP_SHELL_CLASS) {
            (sidebar(false, is_admin, active, is_member))
            div class=(APP_COLUMN_CLASS) {
                (app_topbar(topbar_title, user, mobile_nav(false, is_admin, active, is_member)))
                main class=(APP_MAIN_CLASS) {
                    div class="pointer-events-none absolute inset-0 bg-gradient-to-br from-indigo-500/[0.02] via-transparent to-teal-500/[0.02]" {}
                    div class="relative" { (content) }
                }
            }
            (feedback_launcher())
        }
        (sse)
    }
}

pub fn admin_shell(user: &User, active: &str, topbar_title: &str, content: Markup) -> Markup {
    let sse = sse_subscriber_script();
    html! {
        div class=(APP_SHELL_CLASS) {
            (sidebar(true, true, active, true))
            div class=(APP_COLUMN_CLASS) {
                (app_topbar(topbar_title, user, mobile_nav(true, true, active, true)))
                main class=(APP_MAIN_CLASS) {
                    div class="relative" { (content) }
                }
            }
            // BUNYIP-370: same launcher the user dashboard carries, so an admin
            // can report from the panel they are looking at.
            (feedback_launcher())
        }
        (sse)
    }
}

/// A single settings/content block: a card with a title, an optional subtitle,
/// and a body. The building unit of the two-column admin block layout
/// (BUNYIP-415), so sparse full-width admin screens group related controls into
/// blocks instead of one long narrow column. Matches the inline card markup
/// already used across the admin screens (rounded border + card surface, a
/// header stack, and a padded body).
pub fn admin_block(title: &str, subtitle: Option<&str>, body: Markup) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { (title) }
                @if let Some(s) = subtitle {
                    p class="text-sm text-muted-foreground" { (s) }
                }
            }
            div class="p-6 pt-0" { (body) }
        }
    }
}

/// Lay a set of blocks out in a responsive two-column grid that collapses to a
/// single column below the `lg` breakpoint (BUNYIP-415). `items-start` so
/// blocks of unequal height top-align rather than stretching to match the
/// tallest, and `gap-6` matches the vertical rhythm of the single-column
/// `space-y-6` stacks these screens use elsewhere.
pub fn admin_block_grid(blocks: Vec<Markup>) -> Markup {
    html! {
        div class="grid gap-6 items-start lg:grid-cols-2" {
            @for b in blocks { (b) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{MembershipStatus, MembershipTier};

    fn test_user(role: UserRole) -> User {
        User {
            id: "u1".into(),
            email: "u@example.com".into(),
            role,
            email_verified: true,
            two_factor_enabled: true,
            membership_status: MembershipStatus::None,
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            created_at: String::new(),
            updated_at: String::new(),
            membership_tier: MembershipTier::Free,
            trial_ends_at: None,
            lifetime_member: false,
            first_name: Some("Ada".into()),
            last_name: Some("Lovelace".into()),
            phone: None,
            avatar_updated_at: None,
            is_super_admin: false,
        }
    }

    /// Attributes of the first `<tag ...>` in `html`.
    fn first_tag<'a>(html: &'a str, tag: &str) -> &'a str {
        let rest = html
            .split_once(&format!("<{tag}"))
            .unwrap_or_else(|| panic!("markup contains a <{tag}>"))
            .1;
        rest.split_once('>').expect("the tag closes").0
    }

    /// BUNYIP-368: scrolling the sidebar used to scroll the whole document,
    /// because the shell was `min-h-screen` (free to grow past the viewport)
    /// and nothing inside the sidebar was a scroll container. The contract:
    /// wherever the sidebar is rendered (md and up) the shell is viewport-
    /// height with the overflow clipped, and the nav and `<main>` each scroll
    /// themselves. Every authenticated shell is checked, so a new one that
    /// re-introduces a document-scrolling layout fails here.
    #[test]
    fn every_authenticated_shell_scrolls_its_sidebar_independently() {
        let admin = test_user(UserRole::Admin);
        let member = test_user(UserRole::Subscriber);
        let shells = [
            (
                "admin_shell",
                admin_shell(&admin, "/admin", "Admin", html! {}).into_string(),
            ),
            (
                "dashboard_shell",
                dashboard_shell(&member, "/dashboard", "Dashboard", html! {}).into_string(),
            ),
        ];
        for (name, markup) in shells {
            let shell = first_tag(&markup, "div");
            assert!(
                shell.contains("md:h-screen") && shell.contains("md:overflow-hidden"),
                "{name}'s shell must be viewport-height where the sidebar exists, \
                 else the document scrolls instead of the panes: {shell}"
            );

            let aside = first_tag(&markup, "aside");
            assert!(
                aside.contains("h-full") && aside.contains("overflow-hidden"),
                "{name}'s sidebar must fill the shell and clip its own overflow: {aside}"
            );

            let (sidebar_markup, _) = markup
                .split_once("</aside>")
                .expect("the sidebar element closes");
            let nav = first_tag(sidebar_markup, "nav");
            assert!(
                nav.contains("overflow-y-auto") && nav.contains("flex-1"),
                "{name}'s sidebar nav must be the scroll container: {nav}"
            );

            let main = first_tag(&markup, "main");
            assert!(
                main.contains("overflow-y-auto"),
                "{name}'s content pane must scroll on its own: {main}"
            );
        }
    }

    /// BUNYIP-367: `admin_block_grid` is the shared multi-card container of the
    /// admin screens, so it is where a dropped `gap-*` would silently push
    /// every block's border against its neighbour's.
    #[test]
    fn admin_blocks_are_spaced_from_each_other() {
        let blocks = vec![
            admin_block("Identity", None, html! { p { "a" } }),
            admin_block("Details", Some("sub"), html! { p { "b" } }),
            admin_block("Distribution", None, html! { p { "c" } }),
        ];
        let html = admin_block_grid(blocks).into_string();
        crate::views::ui::assert_cards_are_spaced(&html);
    }

    /// BUNYIP-370: the feedback entry point belongs on EVERY authenticated
    /// surface, not just the user dashboard. This is the guard for the
    /// invariant: adding a new authenticated shell that forgets the launcher
    /// (as `admin_shell` did) fails here.
    #[test]
    fn every_authenticated_shell_mounts_the_feedback_launcher() {
        let admin = test_user(UserRole::Admin);
        let member = test_user(UserRole::Subscriber);
        let shells = [
            (
                "admin_shell",
                admin_shell(&admin, "/admin", "Admin", html! {}).into_string(),
            ),
            (
                "dashboard_shell",
                dashboard_shell(&member, "/dashboard", "Dashboard", html! {}).into_string(),
            ),
        ];
        for (name, markup) in shells {
            assert!(
                markup.contains("data-feedback-link"),
                "{name} must mount the feedback launcher"
            );
            assert!(
                markup.contains(r#"href="/feedback""#),
                "{name}'s launcher must point at the existing /feedback route"
            );
            assert!(
                markup.contains("Have feedback?"),
                "{name}'s launcher must render its label"
            );
        }
    }

    /// BUNYIP-547: `sidebar()` is `hidden md:flex`, so on a phone it rendered
    /// nothing and every nav destination was reachable only by typing the URL.
    /// The invariant: every entry of a shell's nav list is reachable with
    /// the sidebar removed. Mirrors
    /// `every_authenticated_shell_mounts_the_feedback_launcher` - a new shell
    /// that ships the sidebar as its only nav fails here.
    #[test]
    fn every_authenticated_shell_navigates_below_the_md_breakpoint() {
        let admin = test_user(UserRole::Admin);
        let member = test_user(UserRole::Subscriber);
        let shells = [
            (
                "admin_shell",
                admin_shell(&admin, "/admin", "Admin", html! {}).into_string(),
                shell_nav_sections(true, true, true),
            ),
            (
                "dashboard_shell",
                dashboard_shell(&member, "/dashboard", "Dashboard", html! {}).into_string(),
                shell_nav_sections(
                    false,
                    member.role == UserRole::Admin,
                    crate::util::has_active_membership(Some(&member)),
                ),
            ),
        ];
        for (name, markup, sections) in shells {
            let aside = first_tag(&markup, "aside");
            assert!(
                aside.contains("hidden") && aside.contains("md:flex"),
                "{name}'s sidebar is still the wide-viewport-only column this guard is about: {aside}"
            );

            // Everything the sidebar contributes, dropped: what remains is what
            // a 375px viewport actually renders.
            let (before, after) = markup
                .split_once("<aside")
                .expect("the shell renders a sidebar");
            let (_, after) = after.split_once("</aside>").expect("the sidebar closes");
            let small = format!("{before}{after}");
            assert!(
                !small.contains("<aside"),
                "{name} renders more than one sidebar; this guard only strips the first"
            );

            let nav = small
                .split_once("data-mobile-nav")
                .unwrap_or_else(|| panic!("{name} mounts the below-md nav disclosure"))
                .1;
            let nav = nav
                .split_once("</details>")
                .expect("the disclosure closes")
                .0;

            let hrefs: Vec<&str> = sections.iter().flatten().map(|i| i.href).collect();
            assert!(hrefs.len() > 1, "{name}'s nav list is not empty");
            for href in hrefs {
                assert!(
                    nav.contains(&format!(r#"href="{href}""#)),
                    "{name} drops {href} below the md breakpoint: {nav}"
                );
            }
        }
    }

    /// BUNYIP-506: a role string this build does not recognise decodes to
    /// `UserRole::Unknown`, which must gate nothing open. The dashboard shell
    /// is the render-level guard: an Unknown role gets the member sidebar, with
    /// no admin entry point.
    #[test]
    fn an_unknown_role_gets_no_admin_surface() {
        let markup = dashboard_shell(
            &test_user(UserRole::Unknown),
            "/dashboard",
            "Dashboard",
            html! {},
        )
        .into_string();
        assert!(
            !markup.contains(r#"href="/admin"#),
            "an unrecognised role must not reach any admin link: {markup}"
        );
        // Sanity: the same shell for a real admin does carry one, so the
        // assertion above is not passing vacuously.
        let admin = dashboard_shell(
            &test_user(UserRole::Admin),
            "/dashboard",
            "Dashboard",
            html! {},
        )
        .into_string();
        assert!(
            admin.contains(r#"href="/admin"#),
            "admin keeps the panel link"
        );
    }

    /// The admin panel's own "review submitted feedback" page is a different
    /// thing from the "send feedback" launcher; the panel carries both and the
    /// launcher must not be mistaken for the nav entry (BUNYIP-370).
    #[test]
    fn admin_panel_has_both_the_review_page_and_the_send_launcher() {
        let markup = admin_shell(
            &test_user(UserRole::Admin),
            "/admin/users",
            "Users",
            html! {},
        )
        .into_string();
        assert!(
            markup.contains(r#"href="/admin/feedback""#),
            "admin nav keeps the feedback review page"
        );
        assert!(
            markup.contains(r#"aria-label="Open feedback page""#),
            "admin shell also carries the submit-feedback launcher"
        );
    }

    /// BUNYIP-424 (render-level guard, paired with
    /// `security::tests::no_inline_script_or_event_handlers_in_views`): the
    /// document every SSR page is built from must load scripts only from
    /// `'self'`, or the `script-src 'self'` policy silently breaks the app.
    #[test]
    fn document_head_loads_only_first_party_scripts() {
        let html = document("Test", html! {}).into_string();

        assert!(html.contains(r#"src="/assets/vendor/htmx-2.0.3.min.js?v="#));
        assert!(html.contains(r#"src="/assets/js/theme.js?v="#));
        assert!(html.contains(r#"src="/assets/js/app.js?v="#));
        assert!(!html.contains("kit.fontawesome.com"));
        assert!(!html.contains("unpkg.com"));

        // Every <script> is a same-origin src with an empty body.
        for tag in html.split("<script").skip(1) {
            let (attrs, rest) = tag.split_once('>').expect("script tag closes");
            assert!(
                attrs.contains(r#"src="/assets/"#),
                "script without a same-origin src: <script{attrs}>"
            );
            assert!(
                rest.starts_with("</script>"),
                "script with an inline body: <script{attrs}>"
            );
        }
    }

    /// BUNYIP-554 F9: `/assets` is served `max-age=31536000, immutable`, so an
    /// unversioned reference in the head is permanently un-updatable. Every
    /// `/assets/*` URL the shared document emits must carry the build-derived
    /// `?v=`; a reference added without `asset()` fails here.
    #[test]
    fn every_shared_asset_reference_carries_the_build_version() {
        let html = document_with_avatar_picker("Test", html! {}, true).into_string();
        let version = asset_version();
        assert!(!version.is_empty(), "build.rs must emit ASSET_VERSION");

        let mut refs = 0;
        for (attr, quote) in [("src=\"", '"'), ("href=\"", '"')] {
            for piece in html.split(attr).skip(1) {
                let url = piece.split(quote).next().expect("attribute closes");
                if !url.starts_with("/assets/") {
                    continue;
                }
                refs += 1;
                assert!(
                    url.ends_with(&format!("?v={version}")),
                    "unversioned /assets reference: {url} - route it through layout::asset()"
                );
            }
        }
        assert!(
            refs >= 12,
            "expected the whole head to be scanned, saw {refs} /assets references"
        );
    }

    /// BUNYIP-554 F6: the avatar picker renders on exactly one page, so its
    /// stylesheet and controller ship on that page alone. The shell's avatar
    /// slot keeps its one rule everywhere, or every other page loses the
    /// topbar avatar.
    #[test]
    fn the_avatar_picker_ships_only_where_it_renders() {
        let plain = document("Test", html! {}).into_string();
        assert!(
            !plain.contains("avatar-picker"),
            "the picker's CSS / controller must not ship on pages that do not render it"
        );
        assert!(
            plain.contains(".avatar-slot__img"),
            "the shell avatar still needs its slot rule on every page"
        );

        let with_picker = document_with_avatar_picker("Test", html! {}, true).into_string();
        assert!(with_picker.contains(".avatar-picker__trigger"));
        assert!(with_picker.contains("/assets/js/avatar-picker.js?v="));
        assert!(with_picker.contains(".avatar-slot__img"));
    }

    /// BUNYIP-549: the browser-chrome colour used to be two hex literals in
    /// `document()`, so a skin recoloured every in-page token and left the
    /// Android address bar / iOS status bar reed-green. Both metas now come
    /// from config: unset renders the bunyip defaults byte-for-byte, and an
    /// installed pair moves both. One test, because the values live behind a
    /// process-wide `OnceLock` that can only be set once.
    #[test]
    fn theme_color_metas_default_to_bunyip_and_follow_the_skin() {
        let unskinned = document("Test", html! {}).into_string();
        assert!(
            unskinned.contains(&format!(
                r#"<meta name="theme-color" media="(prefers-color-scheme: light)" content="{}">"#,
                crate::config::DEFAULT_THEME_COLOR_LIGHT
            )),
            "unskinned head is unchanged: {unskinned}"
        );
        assert!(
            unskinned.contains(&format!(
                r#"<meta name="theme-color" media="(prefers-color-scheme: dark)" content="{}">"#,
                crate::config::DEFAULT_THEME_COLOR_DARK
            )),
            "unskinned head is unchanged: {unskinned}"
        );

        install_theme_colors("#123456", "#654321");
        let skinned = document("Test", html! {}).into_string();
        assert!(
            skinned.contains(
                r##"<meta name="theme-color" media="(prefers-color-scheme: light)" content="#123456">"##
            ),
            "the light meta follows the skin: {skinned}"
        );
        assert!(
            skinned.contains(
                r##"<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#654321">"##
            ),
            "the dark meta follows the skin: {skinned}"
        );
    }

    /// BUNYIP-487: `/pricing` 404s unless an admin published it, so the nav and
    /// footer links exist on exactly that condition. A link to a 404 and a live
    /// route with no link are both half-finished.
    #[test]
    fn pricing_links_track_whether_the_page_exists() {
        let cfg = Config::from_env();
        let shown = public_shell(&cfg, None, &[], true, false, html! {}).into_string();
        assert_eq!(
            shown.matches(r#"href="/pricing""#).count(),
            2,
            "nav link + footer link when the page is published"
        );

        let hidden = public_shell(&cfg, None, &[], false, false, html! {}).into_string();
        assert!(
            !hidden.contains("/pricing"),
            "no rendered page links to a 404 pricing route"
        );
        // The rest of the chrome is untouched by the switch.
        assert!(hidden.contains(r#"href="/our-story""#));
        assert!(hidden.contains(r#"href="/roadmap""#));
    }

    /// The admin nav reads "Pricing Tiers" while the route stays put, so
    /// existing bookmarks keep working (BUNYIP-487, re-cased in BUNYIP-551).
    #[test]
    fn admin_nav_renames_tier_settings_without_moving_it() {
        let item = admin_items()
            .into_iter()
            .find(|i| i.href == "/admin/tier-settings")
            .expect("the tier-settings entry is still mounted at its old route");
        assert_eq!(item.title, "Pricing Tiers");
    }

    /// BUNYIP-551: one casing for every admin section name. The sidebar label is
    /// also the topbar title and the page h1, so a sentence-case entry here is a
    /// sentence-case heading on the page too.
    #[test]
    fn admin_nav_titles_are_title_case() {
        for item in admin_items() {
            for word in item.title.split(' ') {
                let first = word.chars().next().expect("no empty word in a nav title");
                assert!(
                    first.is_uppercase(),
                    "admin nav entry {:?} ({}) is not Title Case: {word:?} starts lowercase",
                    item.title,
                    item.href
                );
            }
        }
    }

    /// BUNYIP-561: a fully populated record emits the whole sharing set, and
    /// `og:title` matches `<title>` so the two never disagree.
    #[test]
    fn a_populated_record_emits_the_whole_sharing_set() {
        let branding = Branding {
            brand_name: "Acme".into(),
            tagline: "Surfaces what matters.".into(),
            meta_description: "Acme does things.".into(),
            og_image_url: "https://acme.test/card.png".into(),
        };
        assert_eq!(document_title("Dashboard", &branding), "Dashboard · Acme");

        let head = social_meta("Dashboard", &branding).into_string();
        for expected in [
            r#"<meta property="og:type" content="website">"#,
            r#"<meta name="twitter:card" content="summary_large_image">"#,
            r#"<meta property="og:title" content="Dashboard · Acme">"#,
            r#"<meta name="twitter:title" content="Dashboard · Acme">"#,
            r#"<meta property="og:site_name" content="Acme">"#,
            r#"<meta property="og:description" content="Acme does things.">"#,
            r#"<meta name="twitter:description" content="Acme does things.">"#,
            r#"<meta property="og:image" content="https://acme.test/card.png">"#,
            r#"<meta name="twitter:image" content="https://acme.test/card.png">"#,
        ] {
            assert!(head.contains(expected), "missing {expected} in {head}");
        }
        // No og:url: `document()` has no request context, and a wrong canonical
        // URL is worse than none.
        assert!(!head.contains("og:url"));
    }

    /// BUNYIP-561: each empty field omits its own markup, and never substitutes
    /// a literal. That omission is what keeps product copy out of the binary.
    #[test]
    fn each_empty_field_omits_its_own_markup() {
        // Fully empty: no title suffix, no sharing metadata at all.
        let empty = Branding::default();
        assert_eq!(document_title("Dashboard", &empty), "Dashboard");
        assert_eq!(social_meta("Dashboard", &empty).into_string(), "");

        // A name but no image: the small card, and no og:image / twitter:image.
        let named = Branding {
            brand_name: "Acme".into(),
            ..Branding::default()
        };
        let head = social_meta("Dashboard", &named).into_string();
        assert!(head.contains(r#"<meta name="twitter:card" content="summary">"#));
        assert!(!head.contains("og:image"));
        assert!(!head.contains("twitter:image"));
        assert!(!head.contains("og:description"));
        assert!(!head.contains("twitter:description"));

        // An image but no name: the large card, and no og:site_name.
        let imaged = Branding {
            og_image_url: "https://acme.test/card.png".into(),
            ..Branding::default()
        };
        let head = social_meta("Dashboard", &imaged).into_string();
        assert!(head.contains(r#"<meta name="twitter:card" content="summary_large_image">"#));
        assert!(!head.contains("og:site_name"));
    }

    /// BUNYIP-561: the whole `document()` head follows the installed record,
    /// including `<meta name="description">`, which is omitted rather than
    /// falling back to the sentence that used to be compiled in.
    #[test]
    fn the_document_head_follows_the_installed_branding() {
        // One test, because the record lives behind a process-wide cache.
        let unbranded = document("Test", html! {}).into_string();
        assert!(
            !unbranded.contains(r#"<meta name="description""#),
            "an unbranded head omits the description: {unbranded}"
        );
        assert!(unbranded.contains("<title>Test</title>"));
        assert!(!unbranded.contains("og:"));

        crate::branding::install(Branding {
            brand_name: "Acme".into(),
            tagline: "Surfaces what matters.".into(),
            meta_description: "Acme does things.".into(),
            og_image_url: "https://acme.test/card.png".into(),
        });
        let branded = document("Test", html! {}).into_string();
        assert!(branded.contains(r#"<meta name="description" content="Acme does things.">"#));
        assert!(branded.contains("<title>Test · Acme</title>"));
        assert!(
            branded.contains(r#"<meta property="og:image" content="https://acme.test/card.png">"#)
        );

        // Leave the cache unbranded again so no other test in this binary
        // inherits a brand it did not install.
        crate::branding::install(Branding::default());
    }

    /// BUNYIP-561: the admin panel has a Branding entry, and it is Title Case
    /// like every other section (checked in full by the test above).
    #[test]
    fn the_admin_nav_carries_the_branding_page() {
        assert!(
            admin_items()
                .iter()
                .any(|i| i.href == "/admin/branding" && i.title == "Branding"),
            "the branding record is unreachable without a nav entry"
        );
    }

    /// The SSE subscriber takes its origin as passive markup, never as
    /// interpolated JavaScript (BUNYIP-424).
    #[test]
    fn sse_subscriber_passes_origin_as_a_data_attribute() {
        let markup = sse_subscriber_script().into_string();
        assert!(markup.contains(r#"src="/assets/js/sse.js?v="#));
        assert!(markup.contains("data-api-origin="));
        assert!(markup.ends_with("></script>"));
    }
}
