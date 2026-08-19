//! Shared page fragments reused across handlers.

use maud::{html, Markup};

use crate::ui::icon;

/// Centered auth/token card (icon bubble + title + subtitle + body). The caller
/// wraps this in `public_shell`.
pub fn auth_card(
    icon_name: &str,
    icon_class: &str,
    title: &str,
    subtitle: &str,
    body: Markup,
) -> Markup {
    auth_card_shell(Some((icon_name, icon_class)), title, subtitle, body)
}

/// Like [`auth_card`] but without the icon bubble, for headers that are just
/// title + subtitle (e.g. the login page). Keeps those pages from
/// re-implementing the card shell (BUNYIP-467 F14).
pub fn auth_card_plain(title: &str, subtitle: &str, body: Markup) -> Markup {
    auth_card_shell(None, title, subtitle, body)
}

/// Shared shell behind [`auth_card`] / [`auth_card_plain`]. The icon bubble
/// renders only when `icon` is `Some((name, class))`.
fn auth_card_shell(
    icon_spec: Option<(&str, &str)>,
    title: &str,
    subtitle: &str,
    body: Markup,
) -> Markup {
    html! {
        div class="flex min-h-[calc(100vh-8rem)] items-center justify-center py-12" {
            div class="w-full max-w-md rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 text-center" {
                    @if let Some((icon_name, icon_class)) = icon_spec {
                        div class={ "mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full " (icon_class) } {
                            (icon(icon_name, "h-6 w-6"))
                        }
                    }
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { (title) }
                    @if !subtitle.is_empty() {
                        p class="text-sm text-muted-foreground" { (subtitle) }
                    }
                }
                div class="p-6 pt-0" { (body) }
            }
        }
    }
}
