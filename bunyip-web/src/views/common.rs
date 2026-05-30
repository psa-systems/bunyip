//! Shared page fragments reused across handlers.

use maud::{html, Markup};

use crate::views::ui::icon;

/// Centered auth/token card (icon bubble + title + subtitle + body). The caller
/// wraps this in `public_shell`.
pub fn auth_card(icon_name: &str, icon_class: &str, title: &str, subtitle: &str, body: Markup) -> Markup {
    html! {
        div class="flex min-h-[calc(100vh-8rem)] items-center justify-center py-12" {
            div class="w-full max-w-md rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 text-center" {
                    div class={ "mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full " (icon_class) } {
                        (icon(icon_name, "h-6 w-6"))
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

/// Full-screen spinner (guard/loading states).
pub fn spinner() -> Markup {
    html! {
        div class="flex items-center justify-center min-h-screen" {
            div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" {}
        }
    }
}
