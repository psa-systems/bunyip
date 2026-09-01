//! Generic SSR page-shell scaffolding (lifted from bunyip-web in BUNYIP-589).
//!
//! Consumer-agnostic building blocks the page shells compose: the versioned
//! `/assets` helper, the process-wide install/read `OnceLock`s a `main` sets
//! once (SSE origin, feature flags, skin CSS, browser-chrome colours), the theme
//! toggles, the nav-row renderer, the admin card primitives, and the shell
//! layout class constants. Nothing here names a product, a brand record, a user
//! type, or an app route: the consumer supplies those and builds its own nav
//! data, document `<head>`, and shells on top of these.

use std::sync::atomic::{AtomicBool, Ordering};
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

/// BUNYIP-493: whether the organizations and teams feature is switched on.
/// Installed once from `main` for the same reason [`COMMUNITY_ENABLED`] is: a
/// nav list is built by a free function with no access to per-request state.
///
/// An `AtomicBool` rather than a `OnceLock` because the value comes from an
/// admin switch, not from the environment: a process that read `false` at
/// startup must be able to publish a later reading without a restart, and both
/// states have to be reachable from one test binary. `false` until installed,
/// so a consumer that never installs it leaves the feature dark.
static ORGS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Install the organizations and teams flag. Called from `main`; re-callable, so
/// a consumer that re-reads the switch can publish the new value.
pub fn install_orgs_enabled(enabled: bool) {
    ORGS_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn orgs_enabled() -> bool {
    ORGS_ENABLED.load(Ordering::Relaxed)
}

/// Absolute URL of the committed share image, installed once from the
/// consumer's config. The branding record wins when it carries an uploaded
/// image; this is what an unbranded deployment falls back to, so the Open
/// Graph tags are never simply absent.
static DEFAULT_SHARE_IMAGE: OnceLock<Option<String>> = OnceLock::new();

/// Install the fallback share image. Called once from `main`. Idempotent.
pub fn install_default_share_image(url: Option<String>) {
    let _ = DEFAULT_SHARE_IMAGE.set(url);
}

pub fn default_share_image() -> Option<&'static str> {
    DEFAULT_SHARE_IMAGE.get().and_then(Option::as_deref)
}

/// BUNYIP-560/568: resolve one palette value (a `theme-color` meta, the `:root`
/// ramp): the brand record's value when non-empty, else nothing at all. There is
/// no second source and no compiled-in colour, so an unbranded deployment omits
/// the markup rather than painting one product's palette. Pure, so the omission
/// rule is unit-testable.
pub fn palette_value(record: &str) -> Option<&str> {
    if record.is_empty() {
        None
    } else {
        Some(record)
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
