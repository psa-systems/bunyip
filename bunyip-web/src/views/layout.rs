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

use std::sync::OnceLock;

use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::api::types::{Application, User, UserRole};
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

/// BUNYIP-145 / BUNYIP-424: the browser-facing origin the dashboard's
/// `EventSource` connects to, handed to `assets/js/sse.js` as a `data-` attribute
/// on its own `<script>` tag. Server values reach the client as passive markup,
/// never as executable JavaScript.
fn sse_subscriber_script() -> Markup {
    html! {
        script src="/assets/js/sse.js" data-api-origin=(sse_api_origin()) defer {}
    }
}

pub fn document(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                meta name="description" content="Bunyip - the SaaS layer for your PSA. Auth, billing, members, and identity for Mokosh.";
                meta name="theme-color" media="(prefers-color-scheme: light)" content="#2f4e2e";
                meta name="theme-color" media="(prefers-color-scheme: dark)" content="#161a16";
                title { (title) }
                // BUNYIP-339: favicon set derived from the Bunyip hero art
                // (face crop, rounded corners). Served from /assets via ServeDir.
                link rel="icon" href="/assets/favicon.ico" sizes="any";
                link rel="icon" type="image/png" sizes="16x16" href="/assets/favicon-16x16.png";
                link rel="icon" type="image/png" sizes="32x32" href="/assets/favicon-32x32.png";
                link rel="icon" type="image/png" sizes="48x48" href="/assets/favicon-48x48.png";
                link rel="icon" type="image/png" sizes="192x192" href="/assets/favicon-192x192.png";
                link rel="icon" type="image/png" sizes="512x512" href="/assets/favicon-512x512.png";
                link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png";
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin;
                link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet";
                // BUNYIP-424: Font Awesome is the self-hosted free webfont build,
                // not the kit loader. The kit rotates its own contents by design
                // and cannot carry SRI, so it was a standing remote-code grant to
                // a third party. Vendored under assets/vendor/, version in the
                // path so an upgrade is a visible diff.
                link rel="stylesheet" href="/assets/vendor/fontawesome-6.7.2/css/fontawesome.min.css";
                link rel="stylesheet" href="/assets/vendor/fontawesome-6.7.2/css/solid.min.css";
                link rel="stylesheet" href="/assets/vendor/fontawesome-6.7.2/css/regular.min.css";
                link rel="stylesheet" href="/assets/styles.css";
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
                script src="/assets/vendor/htmx-2.0.3.min.js" defer {}
                // theme.js is NOT deferred: the stored theme has to land on
                // <html> before first paint or the page flashes the wrong theme.
                script src="/assets/js/theme.js" {}
                script src="/assets/js/app.js" defer {}
                // BUNYIP-473: drag-and-drop / keyboard reordering for admin
                // lists. Inert on pages without a `[data-reorder-list]`.
                script src="/assets/js/app-reorder.js" defer {}
                // BUNYIP-408: avatar picker CSS shipped inline (not via the
                // separately-cached styles.css) so a stale stylesheet can never
                // leave the component's structural rules undefined. See
                // `avatar_picker::AVATAR_PICKER_CSS`.
                style { (PreEscaped(crate::views::avatar_picker::AVATAR_PICKER_CSS)) }
                script src="/assets/js/avatar-picker.js" defer {}
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
        svg class="w-7 h-7 text-bunyip-reed-700 dark:text-bunyip-reed-200" viewBox="0 0 32 32" fill="none" {
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
            span class="text-2xl font-semibold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50 group-hover:text-bunyip-reed-700 dark:group-hover:text-bunyip-reed-200 transition-colors" { "Bunyip" }
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
/// viewport. Mounted by `dashboard_shell` (always on for authenticated
/// users) and by `public_shell` (gated by `show_feedback`, kept off on
/// the login / register flow). Pages whose primary action lands in the
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
              class="pointer-events-auto group flex h-14 w-[60px] items-center overflow-hidden rounded-2xl border border-border/70 bg-background/85 text-primary shadow-xl shadow-primary/10 backdrop-blur-md transition-all duration-300 hover:w-[204px] hover:border-primary/50 hover:bg-background dark:bg-card/90 sm:h-16 sm:w-16 sm:hover:w-[214px]" {
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
fn header(user: Option<&User>, _show_feedback: bool) -> Markup {
    let is_admin = user.map(|u| u.role == UserRole::Admin).unwrap_or(false);
    html! {
        header class="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60" {
            div class="container flex h-16 items-center justify-between" {
                div class="flex items-center gap-6" {
                    (brand())
                    nav class="hidden md:flex items-center gap-6" {
                        a href="/pricing" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Pricing" }
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
                        a href="/register" class=(button_class("default", "sm", "")) { "Get Started" }
                        a href="/login" class=(button_class("outline", "sm", "")) { "Login" }
                    }
                }
            }
        }
    }
}

fn footer(cfg: &Config, apps: &[Application]) -> Markup {
    let year = chrono::Utc::now().format("%Y").to_string();
    html! {
        footer class="border-t border-border/50 bg-gradient-to-b from-background to-indigo-950/5 dark:to-indigo-950/30" {
            div class="container py-8 md:py-12" {
                div class="grid grid-cols-2 gap-8 md:grid-cols-4" {
                    div class="col-span-2 md:col-span-1" {
                        (brand())
                        p class="mt-4 text-sm text-muted-foreground" { "Surfaces what matters." }
                        p class="mt-1 text-xs text-muted-foreground" { "Bunyip · " (cfg.domain_or_localhost()) }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Product" }
                        ul class="mt-4 space-y-3 text-sm" {
                            li { a href="/pricing" class="text-muted-foreground hover:text-foreground transition-colors" { "Pricing" } }
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
                            li { a href="/login" class="text-muted-foreground hover:text-foreground transition-colors" { "Login" } }
                            li { a href="/register" class="text-muted-foreground hover:text-foreground transition-colors" { "Register" } }
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
    show_feedback: bool,
    content: Markup,
) -> Markup {
    html! {
        div class="flex min-h-screen flex-col" {
            (header(user, show_feedback))
            main class="flex-1" { (content) }
            (footer(cfg, apps))
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
            title: "Overview",
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
            title: "Groups",
            href: "/admin/application-groups",
            icon: "layers",
        },
        NavItem {
            title: "Entitlements",
            href: "/admin/entitlements",
            icon: "key",
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
            title: "Tier Settings",
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
            title: "Auto-ban",
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

fn sidebar(admin: bool, is_admin: bool, active: &str, is_member: bool) -> Markup {
    let items = if admin {
        admin_items()
    } else {
        dashboard_items(is_member)
    };
    html! {
        aside class="hidden md:flex w-64 flex-col border-r border-border/50 bg-gradient-to-b from-background via-background to-indigo-950/5 dark:to-indigo-950/20" {
            div class="flex h-16 items-center border-b border-border/50 px-6" {
                (brand())
                @if admin {
                    span class="ml-2 rounded bg-gradient-to-r from-indigo-500/20 to-teal-500/20 px-2 py-0.5 text-xs font-medium text-indigo-600 dark:text-indigo-400" { "Admin" }
                }
            }
            nav class="flex-1 space-y-1 p-4" {
                // BUNYIP-417: the user/admin dashboard switch is a top-level,
                // frequently-used control, so it sits at the TOP of the nav
                // (above the section items) rather than buried at the bottom.
                @if !admin && is_admin {
                    a href="/admin" class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors " (NAV_INACTIVE) } {
                        (icon("shield", "h-4 w-4")) "Admin Panel"
                    }
                    div class="my-3 border-t border-border/50" {}
                }
                @if admin {
                    a href="/dashboard" class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors " (NAV_INACTIVE) } {
                        (icon("layout-dashboard", "h-4 w-4")) "User Dashboard"
                    }
                    div class="my-3 border-t border-border/50" {}
                }
                @for item in &items {
                    // BUNYIP-329: Community launches the external Let's Chat
                    // instance, so open it in a new tab and keep the Bunyip tab.
                    @let external = item.href == "/community";
                    a href=(item.href)
                      target=[external.then_some("_blank")]
                      rel=[external.then_some("noopener noreferrer")]
                      class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all " (if active == item.href { NAV_ACTIVE } else { NAV_INACTIVE }) } {
                        (icon(item.icon, "h-4 w-4"))
                        (item.title)
                        // BUNYIP-341: flag the external Community launch with a
                        // trailing external-link glyph (opens in a new tab), so
                        // the row reads as "leaves Bunyip" before it is clicked.
                        @if external {
                            (icon("external-link", "ml-auto h-3.5 w-3.5 opacity-60"))
                        }
                    }
                }
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
                a href="/logout" class="flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-accent transition-colors dark:text-red-400" {
                    (icon("log-out", "h-4 w-4")) "Log out"
                }
            }
        }
    }
}

fn app_topbar(title: &str, user: &User) -> Markup {
    html! {
        // BUNYIP-408: `relative z-40` gives the topbar a stacking context that
        // sits above the scrolling `<main>` content. Without it the profile-menu
        // dropdown (which overflows below the h-16 bar) is painted OVER by the
        // page's cards, so it looked cut off and its rows were neither hoverable
        // nor clickable in the dashboard / admin shells. The public `header`
        // already carries `z-50`, which is why the same component worked there.
        header class="relative z-40 flex h-16 items-center justify-between border-b border-border/50 bg-background/80 backdrop-blur-sm px-6" {
            h1 class="text-lg font-semibold" { (title) }
            div class="flex items-center gap-2" {
                (theme_controls("h-4 w-4"))
                (profile_menu(user))
            }
        }
    }
}

/// `topbar_title` is the heading rendered in the top bar (NOT the browser
/// `<title>`). `dashboard_response` derives it from the page-title argument by
/// stripping the ` · Bunyip` brand suffix - that suffix is redundant in the
/// visual header but is still expected on the browser tab. Pre-stripped here
/// so every handler keeps its existing `dashboard_response(...)` call shape.
pub fn dashboard_shell(user: &User, active: &str, topbar_title: &str, content: Markup) -> Markup {
    let is_admin = user.role == UserRole::Admin;
    let is_member = crate::util::has_active_membership(Some(user));
    let sse = sse_subscriber_script();
    html! {
        div class="flex min-h-screen" {
            (sidebar(false, is_admin, active, is_member))
            div class="flex flex-1 flex-col" {
                (app_topbar(topbar_title, user))
                main class="relative flex-1 overflow-auto p-6" {
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
        div class="flex min-h-screen" {
            (sidebar(true, true, active, true))
            div class="flex flex-1 flex-col" {
                (app_topbar(topbar_title, user))
                main class="relative flex-1 overflow-auto p-6" {
                    div class="relative" { (content) }
                }
            }
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

    /// BUNYIP-424 (render-level guard, paired with
    /// `security::tests::no_inline_script_or_event_handlers_in_views`): the
    /// document every SSR page is built from must load scripts only from
    /// `'self'`, or the `script-src 'self'` policy silently breaks the app.
    #[test]
    fn document_head_loads_only_first_party_scripts() {
        let html = document("Test", html! {}).into_string();

        assert!(html.contains(r#"src="/assets/vendor/htmx-2.0.3.min.js""#));
        assert!(html.contains(r#"src="/assets/js/theme.js""#));
        assert!(html.contains(r#"src="/assets/js/app.js""#));
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

    /// The SSE subscriber takes its origin as passive markup, never as
    /// interpolated JavaScript (BUNYIP-424).
    #[test]
    fn sse_subscriber_passes_origin_as_a_data_attribute() {
        let markup = sse_subscriber_script().into_string();
        assert!(markup.contains(r#"src="/assets/js/sse.js""#));
        assert!(markup.contains("data-api-origin="));
        assert!(markup.ends_with("></script>"));
    }
}
