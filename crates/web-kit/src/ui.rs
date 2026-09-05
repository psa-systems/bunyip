//! Maud UI helpers: button classes, inline lucide icons, badge. Ported from the
//! Dioxus `components/ui` + `components/icons`. Cards/alerts are written inline
//! in pages (plain divs + classes), same as the shadcn markup.

use maud::{html, Markup, PreEscaped};

/// Inner SVG markup for a lucide icon name (24x24, stroke=currentColor).
fn inner(name: &str) -> &'static str {
    match name {
        "sun" => {
            r#"<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>"#
        }
        "moon" => r#"<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>"#,
        "contrast" => r#"<circle cx="12" cy="12" r="10"/><path d="M12 18a6 6 0 0 0 0-12v12z"/>"#,
        "user" => {
            r#"<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>"#
        }
        "log-out" => {
            r#"<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>"#
        }
        "alert-circle" => {
            r#"<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>"#
        }
        "loader" => r#"<path d="M21 12a9 9 0 1 1-6.219-8.56"/>"#,
        "arrow-right" => r#"<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>"#,
        "arrow-left" => r#"<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>"#,
        "external-link" => {
            r#"<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>"#
        }
        "credit-card" => {
            r#"<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/>"#
        }
        "app-window" => {
            r#"<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M10 4v4"/><path d="M2 8h20"/><path d="M6 4v4"/>"#
        }
        "layout-dashboard" => {
            r#"<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>"#
        }
        "banknote" => {
            r#"<rect width="20" height="12" x="2" y="6" rx="2"/><circle cx="12" cy="12" r="2"/><path d="M6 12h.01M18 12h.01"/>"#
        }
        "download" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>"#
        }
        "upload" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>"#
        }
        // BUNYIP-408: caret for the profile-menu disclosure.
        "chevron-down" => r#"<path d="m6 9 6 6 6-6"/>"#,
        // BUNYIP-547: summary glyph of the below-md navigation disclosure.
        "menu" => {
            r#"<line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="18" y2="18"/>"#
        }
        // BUNYIP-405: disclosure chevron for clickable list rows.
        "chevron-right" => r#"<path d="m9 18 6-6-6-6"/>"#,
        // BUNYIP-404: reorder-up affordance (pairs with chevron-down).
        "chevron-up" => r#"<path d="m18 15-6-6-6 6"/>"#,
        // BUNYIP-472 F17: dimmed sortable cue for inactive admin table headers.
        "chevrons-up-down" => r#"<path d="m7 15 5 5 5-5"/><path d="m7 9 5-5 5 5"/>"#,
        // BUNYIP-473: drag handle for the drag-and-drop application reorder.
        "grip-vertical" => {
            r#"<circle cx="9" cy="12" r="1"/><circle cx="9" cy="5" r="1"/><circle cx="9" cy="19" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="15" cy="5" r="1"/><circle cx="15" cy="19" r="1"/>"#
        }
        "receipt" => {
            r#"<path d="M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1Z"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 17.5v-11"/>"#
        }
        "settings" => {
            r#"<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>"#
        }
        "users" => {
            r#"<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>"#
        }
        "file-text" => {
            r#"<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/>"#
        }
        "shield" => r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>"#,
        "shield-check" => {
            r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>"#
        }
        "shield-off" => {
            r#"<path d="M19.7 14a6.9 6.9 0 0 0 .3-2V5l-8-3-3.2 1.2"/><path d="m4.3 4.3 .9 .9 A8 8 0 0 0 4 5v7c0 6 8 10 8 10a20.3 20.3 0 0 0 5.6-4.5"/><line x1="2" x2="22" y1="2" y2="22"/>"#
        }
        "shield-alert" => {
            r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/>"#
        }
        "message-square-quote" => {
            r#"<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="M8 12a2 2 0 0 0 2-2V8H8"/><path d="M14 12a2 2 0 0 0 2-2V8h-2"/>"#
        }
        "smile-plus" => {
            r#"<path d="M22 11v1a10 10 0 1 1-9-10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" x2="9.01" y1="9" y2="9"/><line x1="15" x2="15.01" y1="9" y2="9"/><path d="M16 5h6"/><path d="M19 2v6"/>"#
        }
        "check-circle" => {
            r#"<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>"#
        }
        "check" => r#"<path d="M20 6 9 17l-5-5"/>"#,
        "x" => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
        "mail" => {
            r#"<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>"#
        }
        "copy" => {
            r#"<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>"#
        }
        "trash" => {
            r#"<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>"#
        }
        "key" => {
            r#"<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>"#
        }
        "lock" => {
            r#"<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#
        }
        "alert-triangle" => {
            r#"<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>"#
        }
        "trending-up" => {
            r#"<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>"#
        }
        "activity" => r#"<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>"#,
        "log-in" => {
            r#"<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" x2="3" y1="12" y2="12"/>"#
        }
        "user-plus" => {
            r#"<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" x2="19" y1="8" y2="14"/><line x1="22" x2="16" y1="11" y2="11"/>"#
        }
        "user-cog" => {
            r#"<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><circle cx="19" cy="11" r="2"/><path d="M19 8v1"/><path d="M19 13v1"/><path d="m21.6 9.5-.87.5"/><path d="m17.27 12-.87.5"/><path d="m21.6 12.5-.87-.5"/><path d="m17.27 11-.87-.5"/>"#
        }
        "link-2" => {
            r#"<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" x2="16" y1="12" y2="12"/>"#
        }
        "save" => {
            r#"<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>"#
        }
        "layers" => {
            r#"<path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12"/><path d="M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17"/>"#
        }
        "package" => {
            r#"<path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"/><path d="M12 22V12"/><polyline points="3.29 7 12 12 20.71 7"/><path d="m7.5 4.27 9 5.15"/>"#
        }
        "gauge" => r#"<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>"#,
        "sliders-horizontal" => {
            r#"<line x1="21" x2="14" y1="4" y2="4"/><line x1="10" x2="3" y1="4" y2="4"/><line x1="21" x2="12" y1="12" y2="12"/><line x1="8" x2="3" y1="12" y2="12"/><line x1="21" x2="16" y1="20" y2="20"/><line x1="12" x2="3" y1="20" y2="20"/><line x1="14" x2="14" y1="2" y2="6"/><line x1="8" x2="8" y1="10" y2="14"/><line x1="16" x2="16" y1="18" y2="22"/>"#
        }
        "globe" => {
            r#"<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>"#
        }
        "help-circle" => {
            r#"<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>"#
        }
        // BUNYIP-554: the last glyphs that still came from the Font Awesome
        // webfont. Adding them here retired 240 KB of CSS + woff2 from every
        // page; the rest of the set already had an inline equivalent.
        "circle" => r#"<circle cx="12" cy="12" r="10"/>"#,
        "circle-check" => r#"<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>"#,
        "circle-x" => {
            r#"<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>"#
        }
        "eye" => {
            r#"<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>"#
        }
        "eye-off" => {
            r#"<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>"#
        }
        _ => "",
    }
}

/// Whether `name` resolves to real SVG. `inner()` answers an empty string for
/// an unknown name, which renders an invisible `<svg>` instead of failing, so
/// the guards that keep a typo (or a retired Font Awesome name) from shipping
/// blank need to ask (BUNYIP-554). Public so bunyip-web's icon-scan guard test,
/// which lives in the consuming crate, can call it across the crate boundary.
pub fn icon_is_known(name: &str) -> bool {
    !inner(name).is_empty()
}

pub fn icon(name: &str, class: &str) -> Markup {
    html! {
        svg class=(class) viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" {
            (PreEscaped(inner(name)))
        }
    }
}

fn variant_classes(variant: &str) -> &'static str {
    match variant {
        "destructive" => "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        "outline" => {
            "border border-input bg-background hover:bg-accent hover:text-accent-foreground"
        }
        "secondary" => "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        "ghost" => "hover:bg-accent hover:text-accent-foreground",
        // The brand fill, from the SKINNABLE scale (BUNYIP-656). `bg-primary`
        // is a static hex in `@theme inline`, so it holds the default green
        // through a rebrand; `bg-brand-primary-700` follows `--skin-primary-*`.
        // The two share a default value, which is why the hero CTA passing the
        // brand fill as an `extra` and losing to `bg-primary` looked right.
        "brand" => "bg-brand-primary-700 text-white hover:bg-brand-primary-800",
        // A button sitting ON the brand gradient: the fill is the light
        // surface and the label the brand's darkest step (BUNYIP-656). It is a
        // variant rather than an `extra` on `default`, because `extra` cannot
        // override a colour the variant already names: two utilities for one
        // property resolve by stylesheet order, not class-attribute order, and
        // `.text-primary-foreground` sorts after every `.text-brand-*`, so the
        // label rendered white on the white fill and vanished.
        "inverse" => "bg-white text-brand-primary-800",
        "link" => "text-primary-text underline-offset-4 hover:underline",
        _ => "bg-primary text-primary-foreground hover:bg-primary/90",
    }
}

fn size_classes(size: &str) -> &'static str {
    match size {
        // Sits inside a table row, where `sm` is a line taller than the row's
        // own rhythm; pairs with `text-xs` (BUNYIP-656).
        "xs" => "h-8 rounded-md px-2",
        "sm" => "h-9 rounded-md px-3",
        "lg" => "h-11 rounded-md px-8",
        "icon" => "h-10 w-10",
        _ => "h-10 px-4 py-2",
    }
}

const BTN_BASE: &str = "relative inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50";

pub fn button_class(variant: &str, size: &str, extra: &str) -> String {
    format!(
        "{BTN_BASE} {} {} {extra}",
        variant_classes(variant),
        size_classes(size)
    )
}

/// The one "return to the parent surface" affordance (BUNYIP-550 F6). Every
/// surface with a parent renders this, so back navigation is one treatment
/// instead of the four it had grown (muted text link with a literal arrow,
/// bare underline link, outline button, filled button). It is navigation, not
/// an action, so it resolves to the `link` variant's colour rather than a
/// button, and the direction cue is the lucide glyph rather than a hardcoded
/// character that renders in the body font and ignores the icon classes.
pub fn back_link(href: &str, label: &str) -> Markup {
    html! {
        a href=(href) class="inline-flex items-center gap-1 text-sm text-primary-text hover:underline" {
            (icon("arrow-left", "h-4 w-4"))
            (label)
        }
    }
}

/// Prev/Next pager shared by the admin tables and the two `/settings` lists
/// (BUNYIP-467 F15). `base` is the path (optionally already carrying query
/// params) and `param` is the page query key: `page` for the admin tables, and
/// `session_page` / `device_page` for the two independent `/settings` lists, so
/// two pagers can coexist on one page without their page numbers colliding.
/// Plain links (no htmx).
pub fn pager(base: &str, param: &str, page: u32, total_pages: i64) -> Markup {
    let sep = if base.contains('?') { "&" } else { "?" };
    html! {
        @if total_pages > 1 {
            div class="flex justify-center gap-2 mt-6" {
                @if page > 1 { a href=(format!("{base}{sep}{param}={}", page - 1)) class=(button_class("outline", "sm", "")) { "Previous" } }
                span class="flex items-center px-3 text-sm" { "Page " (page) " of " (total_pages) }
                @if (page as i64) < total_pages { a href=(format!("{base}{sep}{param}={}", page + 1)) class=(button_class("outline", "sm", "")) { "Next" } }
            }
        }
    }
}

pub fn badge(variant: &str, text: &str) -> Markup {
    let v = match variant {
        "secondary" => "border-transparent bg-secondary text-secondary-foreground",
        "destructive" => "border-transparent bg-destructive text-destructive-foreground",
        "outline" => "text-foreground",
        "success" => "border-transparent bg-teal-500/15 text-teal-600 dark:text-teal-400",
        "warning" => "border-transparent bg-amber-500/15 text-amber-800 dark:text-amber-300",
        _ => "border-transparent bg-primary text-primary-foreground",
    };
    html! {
        span class={ "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors " (v) } { (text) }
    }
}

/// A form-submit toggle switch (BUNYIP-420). The control itself is the submit
/// button, so a single click posts the flipped value through the enclosing
/// form. `on` colors the track (primary) and slides the knob right; off is a
/// muted track with the knob left. `label` names it for assistive tech
/// (`role="switch"` + `aria-checked` + `aria-label`) since the state is
/// conveyed only by color / position, not text.
pub fn toggle_switch(on: bool, label: &str) -> Markup {
    let track = if on {
        "bg-primary"
    } else {
        "bg-muted-foreground/40"
    };
    let knob = if on {
        "translate-x-[22px]"
    } else {
        "translate-x-0.5"
    };
    html! {
        button type="submit" role="switch"
          aria-checked=(if on { "true" } else { "false" })
          aria-label=(label)
          class={ "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 " (track) } {
            span class={ "inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform " (knob) } {}
        }
    }
}

/// Cap a banner message before it is rendered. The value is already
/// Maud-escaped (so this is not an XSS guard); it bounds a hand-crafted
/// `?ok=` / `?error=` link that stuffs the param with kilobytes of text to blow
/// up the page. ~256 bytes is ample for the short status strings these banners
/// legitimately carry. Truncation lands on a char boundary. Applied inside
/// [`error_box`] and [`success_box`] so every banner caller is bounded without
/// each having to remember to clamp (BUNYIP-324).
fn clamp_msg(s: &str) -> String {
    const MAX: usize = 256;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Destructive inline error box (replaces the shadcn Alert for error display).
pub fn error_box(msg: &str) -> Markup {
    html! {
        div class="rounded-lg border border-destructive/50 p-3 text-sm text-destructive-text flex items-center gap-2" {
            (icon("alert-circle", "h-4 w-4"))
            (clamp_msg(msg))
        }
    }
}

/// BUNYIP-516: an [`error_box`] whose parts are rendered as separate lines: a
/// headline saying what bunyip could not do, an optional cause, and an optional
/// bunyip-api request id to quote. Each line is clamped on its own, so a
/// two-sentence explanation plus a reference is not cut off at 256 characters
/// the way one concatenated string would be.
pub fn error_box_detailed(headline: &str, cause: Option<&str>, reference: Option<&str>) -> Markup {
    html! {
        div class="rounded-lg border border-destructive/50 p-3 text-sm text-destructive-text flex items-start gap-2" {
            (icon("alert-circle", "h-4 w-4 mt-0.5 shrink-0"))
            div class="space-y-1" {
                p { (clamp_msg(headline)) }
                @if let Some(c) = cause {
                    p { (clamp_msg(c)) }
                }
                @if let Some(r) = reference {
                    p class="text-xs font-mono" { "Reference: " (clamp_msg(r)) }
                }
            }
        }
    }
}

/// Success / confirmation banner, the teal-check counterpart to [`error_box`].
/// Matches the inline `?ok=` banner the settings page renders, so the
/// onboarding page can show the same "verification email sent" feedback for a
/// resend that originated there (BUNYIP-324).
pub fn success_box(msg: &str) -> Markup {
    html! {
        div class="rounded-lg border p-3 text-sm flex items-center gap-2" {
            (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400"))
            (clamp_msg(msg))
        }
    }
}

/// BUNYIP-468: the one shared list empty-state - centered column, large muted
/// icon, muted message, optional CTA below. Every `is_empty()` list branch routes here.
pub fn empty_state(icon_name: &str, message: &str, cta: Option<Markup>) -> Markup {
    html! {
        div class="flex flex-col items-center justify-center py-12 text-center" {
            (icon(icon_name, "h-10 w-10 text-muted-foreground/60 mb-3"))
            p class="text-muted-foreground" { (message) }
            @if let Some(c) = cta {
                div class="mt-4" { (c) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{clamp_msg, empty_state, error_box, icon, success_box, toggle_switch};

    /// BUNYIP-420: the toggle switch reflects state via color + knob position
    /// and carries the right ARIA, so it reads as an on/off control (not text).
    #[test]
    fn toggle_switch_reflects_on_and_off_state() {
        let on = toggle_switch(true, "Toggle active").into_string();
        assert!(on.contains(r#"aria-checked="true""#));
        assert!(on.contains("bg-primary"), "on state colors the track");
        assert!(
            on.contains("translate-x-[22px]"),
            "on slides the knob right"
        );
        assert!(on.contains(r#"role="switch""#) && on.contains(r#"aria-label="Toggle active""#));
        assert!(
            on.contains(r#"type="submit""#),
            "the switch is the form submit control"
        );

        let off = toggle_switch(false, "Toggle maintenance mode").into_string();
        assert!(off.contains(r#"aria-checked="false""#));
        assert!(
            !off.contains("bg-primary"),
            "off state is not primary-colored"
        );
        assert!(off.contains("translate-x-0.5"), "off keeps the knob left");
    }

    /// BUNYIP-404: the reorder arrows must resolve to a real glyph, not the
    /// empty-`inner` fallback (which would render a blank button). Guards both
    /// directions used by the application-reorder controls.
    #[test]
    fn reorder_chevrons_render_a_path() {
        for name in ["chevron-up", "chevron-down"] {
            let svg = icon(name, "h-4 w-4").into_string();
            assert!(
                svg.contains("<path"),
                "icon(\"{name}\") should render an SVG path, not the empty fallback"
            );
        }
    }

    /// BUNYIP-468: the shared empty-state renders the centered py-12 block with
    /// the named icon and message, and only wraps a CTA when one is passed.
    #[test]
    fn empty_state_renders_icon_message_and_optional_cta() {
        let plain = empty_state("users", "No users yet.", None).into_string();
        assert!(
            plain.contains("py-12"),
            "empty state is the centered py-12 block"
        );
        assert!(plain.contains("No users yet."));
        assert!(plain.contains("<svg"), "renders the named icon");
        assert!(!plain.contains("mt-4"), "no CTA wrapper when cta is None");

        let with_cta = empty_state(
            "users",
            "No matches",
            Some(maud::html! { a href="/x" { "Clear" } }),
        )
        .into_string();
        assert!(
            with_cta.contains("mt-4") && with_cta.contains("Clear"),
            "CTA renders in its own wrapper below the message"
        );
    }

    #[test]
    fn clamp_passes_short_through() {
        assert_eq!(
            clamp_msg("Verification email sent to u@example.com"),
            "Verification email sent to u@example.com"
        );
    }

    #[test]
    fn clamp_bounds_oversized_input() {
        let long = "a".repeat(10_000);
        assert_eq!(clamp_msg(&long).len(), 256);
    }

    #[test]
    fn clamp_lands_on_char_boundary() {
        // 3-byte chars straddle the 256-byte cap (256 % 3 != 0); the boundary
        // walk must step back rather than panic on a mid-char slice.
        let s = "\u{20ac}".repeat(100); // 300 bytes of U+20AC (euro sign)
        let out = clamp_msg(&s);
        assert!(out.len() <= 256);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn banners_clamp_their_message() {
        // The clamp is applied inside the shared banner helpers, so an
        // oversized ?ok= / ?error= param cannot bloat the rendered page.
        let long = "z".repeat(10_000);
        assert!(success_box(&long).into_string().matches('z').count() <= 256);
        assert!(error_box(&long).into_string().matches('z').count() <= 256);
    }

    /// Fixing the `link` variant at the source fixes every `button_class`
    /// caller, so no caller has to remember the token.
    #[test]
    fn link_variant_uses_the_foreground_token() {
        assert!(super::variant_classes("link").contains("text-primary-text"));
    }

    /// The one back-link treatment: navigation colour, not a button, and the
    /// lucide glyph rather than a hardcoded character (BUNYIP-550 F6).
    #[test]
    fn back_link_is_a_navigation_link_carrying_the_arrow_glyph() {
        let markup = super::back_link("/admin/users", "Back to users").into_string();
        assert!(markup.contains(r#"href="/admin/users""#), "{markup}");
        assert!(markup.contains("text-primary-text"), "{markup}");
        assert!(markup.contains("hover:underline"), "{markup}");
        assert!(!markup.contains(super::BTN_BASE), "{markup}");
        assert!(markup.contains(super::inner("arrow-left")), "{markup}");
    }
}
