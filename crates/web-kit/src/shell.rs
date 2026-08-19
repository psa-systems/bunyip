//! Generic SSR page-shell scaffolding (lifted from bunyip-web in BUNYIP-589).
//!
//! Consumer-agnostic building blocks the page shells compose: the versioned
//! `/assets` helper, the process-wide install/read `OnceLock`s a `main` sets
//! once (SSE origin, feature flags, skin CSS, browser-chrome colours), the theme
//! toggles, the nav-row renderer, the admin card primitives, and the shell
//! layout class constants. Nothing here names a product, a brand record, a user
//! type, or an app route: the consumer supplies those and builds its own nav
//! data, document `<head>`, and shells on top of these.

use std::sync::OnceLock;

use maud::{html, Markup};

use crate::ui::{button_class, icon};

/// The public-facing origin a browser `EventSource` connects to. Set once at
/// startup; read by the authenticated shells so their SSE subscriber can open a
/// stream without threading config through every handler call site.
static SSE_API_ORIGIN: OnceLock<String> = OnceLock::new();

/// Install the public-facing API origin used by the SSE subscriber. Called once
/// from `main` before any request is served. Idempotent.
pub fn install_sse_api_origin(origin: impl Into<String>) {
    let _ = SSE_API_ORIGIN.set(origin.into().trim_end_matches('/').to_string());
}

fn sse_api_origin() -> &'static str {
    SSE_API_ORIGIN
        .get()
        .map(String::as_str)
        .unwrap_or("http://localhost:4401")
}

/// The build-derived cache buster every `/assets/*` reference carries. The
/// consumer serves that directory `max-age=31536000, immutable`, so the query
/// string is the only thing that lets a deploy reach a warm cache. web-kit has
/// no build script of its own, so the consumer installs its own build's version
/// once from `main` (derived by its `build.rs` from the short commit, or the
/// build timestamp when git is absent).
static ASSET_VERSION_CELL: OnceLock<&'static str> = OnceLock::new();

/// Install the consumer's build asset version. Called once from `main` before
/// serving. Idempotent.
pub fn install_asset_version(version: &'static str) {
    let _ = ASSET_VERSION_CELL.set(version);
}

pub fn asset_version() -> &'static str {
    ASSET_VERSION_CELL.get().copied().unwrap_or("dev")
}

/// A versioned `/assets/*` URL. Every reference in the markup goes through this -
/// an unversioned one is served `immutable` and can never be updated.
pub fn asset(path: &str) -> String {
    format!("{path}?v={}", asset_version())
}

/// BUNYIP-329: whether an optional external-community nav entry is shown. Set
/// once from `main`, so a shell can gate the item without threading config
/// through every response caller.
static COMMUNITY_ENABLED: OnceLock<bool> = OnceLock::new();

/// Install the community feature flag. Called once from `main`. Idempotent.
pub fn install_community_enabled(enabled: bool) {
    let _ = COMMUNITY_ENABLED.set(enabled);
}

pub fn community_enabled() -> bool {
    *COMMUNITY_ENABLED.get().unwrap_or(&false)
}

/// BUNYIP-500: optional per-skin theme override (raw CSS custom-property
/// declarations). Set once from `main`; emitted into a `:root` block in the
/// document head. Unset (the default) emits nothing, so the tokens fall back to
/// the default palette.
static SKIN_THEME_CSS: OnceLock<Option<String>> = OnceLock::new();

/// Install the per-skin theme override. Called once from `main`. Idempotent.
pub fn install_skin_theme_css(css: Option<String>) {
    let _ = SKIN_THEME_CSS.set(css);
}

pub fn skin_theme_css() -> Option<&'static str> {
    SKIN_THEME_CSS.get().and_then(Option::as_deref)
}

/// BUNYIP-549: the two `<meta name="theme-color">` values (light, dark) that
/// paint the browser chrome. Bootstrap defaults only: the consumer resolves the
/// running value (e.g. from a brand record) and omits the meta when both the
/// record and these are empty, rather than painting the chrome a literal colour.
static THEME_COLOR_LIGHT: OnceLock<Option<String>> = OnceLock::new();
static THEME_COLOR_DARK: OnceLock<Option<String>> = OnceLock::new();

/// Install the bootstrap browser-chrome colours. Called once from `main`.
/// Idempotent.
pub fn install_theme_colors(light: Option<String>, dark: Option<String>) {
    let _ = THEME_COLOR_LIGHT.set(light);
    let _ = THEME_COLOR_DARK.set(dark);
}

pub fn bootstrap_theme_color_light() -> Option<&'static str> {
    THEME_COLOR_LIGHT.get().and_then(Option::as_deref)
}

pub fn bootstrap_theme_color_dark() -> Option<&'static str> {
    THEME_COLOR_DARK.get().and_then(Option::as_deref)
}

/// BUNYIP-560: resolve one palette value: the record value, else the bootstrap
/// default, else nothing at all. Pure, so the omission rule is unit-testable.
pub fn palette_value<'a>(record: &'a str, bootstrap: Option<&'a str>) -> Option<&'a str> {
    if !record.is_empty() {
        Some(record)
    } else {
        bootstrap.filter(|v| !v.is_empty())
    }
}

/// BUNYIP-145 / BUNYIP-424: the browser-facing origin the dashboard's
/// `EventSource` connects to, handed to the SSE client script as a `data-`
/// attribute. Server values reach the client as passive markup, never as
/// executable JavaScript.
pub fn sse_subscriber_script() -> Markup {
    html! {
        script src=(asset("/assets/js/sse.js")) data-api-origin=(sse_api_origin()) defer {}
    }
}

/// The light/dark and high-contrast toggle buttons. BUNYIP-424:
/// `data-theme-toggle` / `data-contrast-toggle` replace inline click handlers;
/// `assets/js/theme.js` binds them.
pub fn theme_controls(icon_class: &str) -> Markup {
    html! {
        button type="button" aria-label="Toggle theme" class=(button_class("ghost", "icon", "")) data-theme-toggle {
            span class="rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" { (icon("sun", icon_class)) }
            span class="absolute rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" { (icon("moon", icon_class)) }
        }
        button type="button" aria-label="Toggle high contrast" class=(button_class("ghost", "icon", "")) data-contrast-toggle {
            (icon("contrast", icon_class))
        }
    }
}

/// One navigation destination. The consumer builds the section lists (their
/// routes, their icons); `external` marks an entry that leaves this app (opens
/// in a new tab with a trailing glyph) instead of hardcoding any one route here.
pub struct NavItem {
    pub title: &'static str,
    pub href: &'static str,
    pub icon: &'static str,
    pub external: bool,
}

const NAV_ACTIVE: &str =
    "bg-gradient-to-r from-primary to-indigo-500 text-white shadow-md shadow-primary/20";
const NAV_INACTIVE: &str = "text-muted-foreground hover:bg-accent hover:text-accent-foreground";

/// The nav rows, shared by the sidebar and the below-`md` disclosure
/// (BUNYIP-547) so the two cannot drift in destinations, active styling, or
/// external-link handling. Sections are divider-separated.
pub fn nav_links(sections: &[Vec<NavItem>], active: &str) -> Markup {
    html! {
        @for (i, section) in sections.iter().enumerate() {
            @if i > 0 { div class="my-3 border-t border-border/50" {} }
            @for item in section {
                // An external entry opens in a new tab and keeps this one.
                a href=(item.href)
                  target=[item.external.then_some("_blank")]
                  rel=[item.external.then_some("noopener noreferrer")]
                  class={ "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all " (if active == item.href { NAV_ACTIVE } else { NAV_INACTIVE }) } {
                    (icon(item.icon, "h-4 w-4"))
                    (item.title)
                    // BUNYIP-341: flag the external launch with a trailing
                    // external-link glyph, so the row reads as "leaves this app"
                    // before it is clicked.
                    @if item.external {
                        (icon("external-link", "ml-auto h-3.5 w-3.5 opacity-60"))
                    }
                }
            }
        }
    }
}

/// BUNYIP-368: the authenticated shells pin themselves to the viewport from the
/// `md` breakpoint up, so the sidebar and `<main>` are each their own scroll
/// container. Below `md` there is no sidebar, so the page keeps its natural
/// full-document scroll.
pub const APP_SHELL_CLASS: &str = "flex min-h-screen md:h-screen md:overflow-hidden";
/// The content column next to the sidebar: the topbar stays put and only
/// `<main>` inside it scrolls.
pub const APP_COLUMN_CLASS: &str = "flex flex-1 flex-col overflow-hidden";
pub const APP_MAIN_CLASS: &str = "relative flex-1 overflow-y-auto p-6";

/// A single settings/content block: a card with a title, an optional subtitle,
/// and a body. The building unit of the two-column admin block layout
/// (BUNYIP-415), so sparse full-width screens group related controls into blocks
/// instead of one long narrow column.
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
/// single column below the `lg` breakpoint (BUNYIP-415). `items-start` so blocks
/// of unequal height top-align, and `gap-6` matches the single-column rhythm.
pub fn admin_block_grid(blocks: Vec<Markup>) -> Markup {
    html! {
        div class="grid gap-6 items-start lg:grid-cols-2" {
            @for b in blocks { (b) }
        }
    }
}
