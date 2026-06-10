//! Base document + page shells (public / dashboard / admin). Ported from the
//! Dioxus layouts. Theme is handled client-side by a tiny inline script (no
//! reactive framework): an early flash-prevention block + toggle functions that
//! flip classes on <html> and persist to the same `theme-storage` key.

use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::api::types::{Application, User, UserRole};
use crate::config::Config;
use crate::util::app_link;
use crate::views::ui::{button_class, icon};

const THEME_FLASH: &str = r#"(function(){try{var r=document.documentElement;var theme='system',hc=false;var raw=localStorage.getItem('theme-storage');if(raw){var p=JSON.parse(raw);theme=(p&&p.state&&p.state.theme)||'system';hc=!!(p&&p.state&&p.state.highContrast);}var dark=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;r.classList.add(theme==='system'?(dark?'dark':'light'):theme);if(hc)r.classList.add('high-contrast');}catch(e){}})();"#;

const THEME_TOGGLE: &str = r#"function bunyipState(){try{var raw=localStorage.getItem('theme-storage');if(raw)return JSON.parse(raw).state||{};}catch(e){}return{};}
function bunyipSave(t,hc){try{localStorage.setItem('theme-storage',JSON.stringify({state:{theme:t,highContrast:hc},version:0}));}catch(e){}}
function bunyipToggleTheme(){var r=document.documentElement;var dark=r.classList.contains('dark');r.classList.remove('light','dark');var next=dark?'light':'dark';r.classList.add(next);bunyipSave(next,r.classList.contains('high-contrast'));}
function bunyipToggleContrast(){var on=document.documentElement.classList.toggle('high-contrast');bunyipSave(bunyipState().theme||'system',on);}"#;

/// Tiny toast system mounted in every <body>. Exposes `window.bunyipToast(msg, kind)`
/// where `kind` is `"success" | "error" | "info"` (default `"info"`). Each call
/// appends an auto-dismissing pill into `#bunyip-toast-root`.
///
/// Also drains `?toast_ok=` / `?toast_err=` from the URL on page load so any
/// handler that wants to surface a confirmation can do it via a 302 redirect:
/// `Location: /settings?toast_ok=Email%20updated`. The query params are stripped
/// from the URL bar via `history.replaceState` so a reload does not re-fire the
/// toast. See docs/bunyip-upgrade/05-toast-system-and-copy-feedback.md.
const TOAST_JS: &str = r#"window.bunyipToast=function(msg,kind){var root=document.getElementById('bunyip-toast-root');if(!root)return;kind=kind||'info';var palette={success:'bg-emerald-600 text-white',error:'bg-red-600 text-white',info:'bg-slate-800 text-white'}[kind]||'bg-slate-800 text-white';var pill=document.createElement('div');pill.className='pointer-events-auto rounded-md px-4 py-2 text-sm shadow-lg '+palette;pill.setAttribute('role','status');pill.textContent=msg;pill.style.transition='opacity 200ms ease, transform 200ms ease';pill.style.opacity='0';pill.style.transform='translateY(-8px)';root.appendChild(pill);requestAnimationFrame(function(){pill.style.opacity='1';pill.style.transform='translateY(0)';});setTimeout(function(){pill.style.opacity='0';pill.style.transform='translateY(-8px)';setTimeout(function(){if(pill.parentNode)pill.parentNode.removeChild(pill);},250);},2500);};
(function(){try{var url=new URL(window.location.href);var ok=url.searchParams.get('toast_ok');var err=url.searchParams.get('toast_err');if(ok||err){url.searchParams.delete('toast_ok');url.searchParams.delete('toast_err');history.replaceState(null,'',url.pathname+(url.search||'')+url.hash);if(ok)window.bunyipToast(ok,'success');if(err)window.bunyipToast(err,'error');}}catch(e){}})();"#;

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
                link rel="preconnect" href="https://fonts.googleapis.com";
                link rel="preconnect" href="https://fonts.gstatic.com" crossorigin;
                link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet";
                script src="https://kit.fontawesome.com/6ab760c0b1.js" crossorigin="anonymous" {}
                script src="https://unpkg.com/htmx.org@2.0.3" {}
                link rel="stylesheet" href="/assets/styles.css";
                script { (PreEscaped(THEME_FLASH)) }
                script { (PreEscaped(THEME_TOGGLE)) }
                script { (PreEscaped(TOAST_JS)) }
            }
            body {
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
        button type="button" aria-label="Toggle theme" class=(button_class("ghost", "icon", "")) onclick="bunyipToggleTheme()" {
            span class="rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" { (icon("sun", icon_class)) }
            span class="absolute rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" { (icon("moon", icon_class)) }
        }
        button type="button" aria-label="Toggle high contrast" class=(button_class("ghost", "icon", "")) onclick="bunyipToggleContrast()" {
            (icon("contrast", icon_class))
        }
    }
}

/// Top-bar "open feedback" icon button. Replaces the floating launcher that
/// used to sit `fixed bottom-right` and overlap Vervain Agent Download buttons
/// on `/downloads`. Visually mirrors `theme_controls` so the row stays
/// consistent. Mounted by every shell that wants the feedback affordance.
fn feedback_top_button(icon_class: &str) -> Markup {
    html! {
        a href="/feedback" aria-label="Open feedback page"
          class=(button_class("ghost", "icon", "")) {
            (icon("smile-plus", icon_class))
        }
    }
}

/// `show_feedback` mirrors the legacy `launcher: bool` flag on `public_shell`:
/// login / register pages keep the chrome minimal and pass `false`; the
/// marketing pages (Pricing / Our Story / Terms / Privacy) pass `true`. The
/// flag now toggles the top-bar feedback button instead of the floating
/// launcher widget.
fn header(user: Option<&User>, show_feedback: bool) -> Markup {
    let is_admin = user.map(|u| u.role == UserRole::Admin).unwrap_or(false);
    html! {
        header class="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60" {
            div class="container flex h-16 items-center justify-between" {
                div class="flex items-center gap-6" {
                    (brand())
                    nav class="hidden md:flex items-center gap-6" {
                        a href="/pricing" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Pricing" }
                        a href="/our-story" class="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors" { "Our Story" }
                    }
                }
                div class="flex items-center gap-4" {
                    (theme_controls("h-5 w-5"))
                    @if show_feedback { (feedback_top_button("h-5 w-5")) }
                    @if user.is_some() {
                        a href="/dashboard" class=(button_class("ghost", "sm", "")) { "Dashboard" }
                        @if is_admin { a href="/admin" class=(button_class("ghost", "sm", "")) { "Admin" } }
                        a href="/logout" class=(button_class("outline", "sm", "")) { "Logout" }
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
                        p class="mt-1 text-xs text-muted-foreground" { "Bunyip · a8n.systems" }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Product" }
                        ul class="mt-4 space-y-3 text-sm" {
                            li { a href="/pricing" class="text-muted-foreground hover:text-foreground transition-colors" { "Pricing" } }
                            li { a href="/our-story" class="text-muted-foreground hover:text-foreground transition-colors" { "Our Story" } }
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
        }
    }
}

struct NavItem {
    title: &'static str,
    href: &'static str,
    icon: &'static str,
}

fn dashboard_items() -> Vec<NavItem> {
    vec![
        NavItem {
            title: "Dashboard",
            href: "/dashboard",
            icon: "layout-dashboard",
        },
        NavItem {
            title: "Applications",
            href: "/applications",
            icon: "app-window",
        },
        NavItem {
            title: "Downloads",
            href: "/downloads",
            icon: "download",
        },
        NavItem {
            title: "Membership",
            href: "/membership",
            icon: "credit-card",
        },
        NavItem {
            title: "Billing",
            href: "/billing",
            icon: "receipt",
        },
        NavItem {
            title: "Settings",
            href: "/settings",
            icon: "settings",
        },
    ]
}

fn admin_items() -> Vec<NavItem> {
    vec![
        NavItem {
            title: "Overview",
            href: "/admin",
            icon: "layout-dashboard",
        },
        NavItem {
            title: "Users",
            href: "/admin/users",
            icon: "users",
        },
        NavItem {
            title: "Memberships",
            href: "/admin/memberships",
            icon: "credit-card",
        },
        NavItem {
            title: "Applications",
            href: "/admin/applications",
            icon: "app-window",
        },
        NavItem {
            title: "Entitlements",
            href: "/admin/entitlements",
            icon: "key",
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
    ]
}

const NAV_ACTIVE: &str =
    "bg-gradient-to-r from-primary to-indigo-500 text-white shadow-md shadow-primary/20";
const NAV_INACTIVE: &str = "text-muted-foreground hover:bg-accent hover:text-accent-foreground";

fn sidebar(admin: bool, is_admin: bool, active: &str) -> Markup {
    let items = if admin {
        admin_items()
    } else {
        dashboard_items()
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
                @for item in &items {
                    a href=(item.href)
                      class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all " (if active == item.href { NAV_ACTIVE } else { NAV_INACTIVE }) } {
                        (icon(item.icon, "h-4 w-4"))
                        (item.title)
                    }
                }
                @if !admin && is_admin {
                    div class="my-4 border-t border-border/50" {}
                    a href="/admin" class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors " (NAV_INACTIVE) } {
                        (icon("shield", "h-4 w-4")) "Admin Panel"
                    }
                }
                @if admin {
                    div class="my-4 border-t border-border/50" {}
                    a href="/dashboard" class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors " (NAV_INACTIVE) } {
                        (icon("layout-dashboard", "h-4 w-4")) "User Dashboard"
                    }
                }
            }
        }
    }
}

fn app_topbar(title: &str, user: &User) -> Markup {
    html! {
        header class="flex h-16 items-center justify-between border-b border-border/50 bg-background/80 backdrop-blur-sm px-6" {
            h1 class="text-lg font-semibold" { (title) }
            div class="flex items-center gap-4" {
                div class="flex items-center gap-2 text-sm text-muted-foreground" {
                    (icon("user", "h-4 w-4"))
                    span { (user.email) }
                }
                (theme_controls("h-4 w-4"))
                (feedback_top_button("h-4 w-4"))
                a href="/logout" class=(button_class("ghost", "sm", "")) { (icon("log-out", "h-4 w-4")) }
            }
        }
    }
}

pub fn dashboard_shell(user: &User, active: &str, content: Markup) -> Markup {
    let is_admin = user.role == UserRole::Admin;
    html! {
        div class="flex min-h-screen" {
            (sidebar(false, is_admin, active))
            div class="flex flex-1 flex-col" {
                (app_topbar("Dashboard", user))
                main class="relative flex-1 overflow-auto p-6" {
                    div class="pointer-events-none absolute inset-0 bg-gradient-to-br from-indigo-500/[0.02] via-transparent to-teal-500/[0.02]" {}
                    div class="relative" { (content) }
                }
            }
        }
    }
}

pub fn admin_shell(user: &User, active: &str, content: Markup) -> Markup {
    html! {
        div class="flex min-h-screen" {
            (sidebar(true, true, active))
            div class="flex flex-1 flex-col" {
                (app_topbar("Admin", user))
                main class="relative flex-1 overflow-auto p-6" {
                    div class="relative" { (content) }
                }
            }
        }
    }
}
