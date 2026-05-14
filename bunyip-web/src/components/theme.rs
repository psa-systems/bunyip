//! Light/dark theme toggle. The initial theme is set by the early script in
//! `index.html` (so the page renders in the right color scheme before WASM
//! mounts). After WASM is alive, this component reads + flips the `dark`
//! class on `<html>` and persists the choice to localStorage.

use dioxus::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
}

impl Theme {
    fn toggle(self) -> Self {
        match self {
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Light,
        }
    }

    fn class(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

fn read_current_theme() -> Theme {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        return Theme::Light;
    };
    let Some(html) = doc.document_element() else {
        return Theme::Light;
    };
    if html.class_list().contains("dark") {
        Theme::Dark
    } else {
        Theme::Light
    }
}

fn apply_theme(theme: Theme) {
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Some(html) = window.document().and_then(|d| d.document_element()) {
        let list = html.class_list();
        match theme {
            Theme::Dark => {
                let _ = list.add_1("dark");
            }
            Theme::Light => {
                let _ = list.remove_1("dark");
            }
        }
    }
    if let Ok(Some(storage)) = window.local_storage() {
        let _ = storage.set_item("bunyip-theme", theme.class());
    }
}

#[component]
pub fn ThemeToggle() -> Element {
    let mut theme = use_signal(read_current_theme);

    let toggle = move |_| {
        let next = theme().toggle();
        theme.set(next);
        apply_theme(next);
    };

    let is_dark = theme() == Theme::Dark;
    let aria = if is_dark {
        "Switch to light mode"
    } else {
        "Switch to dark mode"
    };

    rsx! {
        button {
            r#type: "button",
            "aria-label": "{aria}",
            class: "shrink-0 inline-flex items-center justify-center w-9 h-9 rounded-md text-bunyip-reed-700 hover:bg-bunyip-reed-50 dark:text-bunyip-reed-200 dark:hover:bg-bunyip-reed-800 transition-colors",
            onclick: toggle,
            if is_dark { SunIcon {} } else { MoonIcon {} }
        }
    }
}

#[component]
fn SunIcon() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            circle { cx: "12", cy: "12", r: "4" }
            path { d: "M12 3v2 M12 19v2 M3 12h2 M19 12h2 M5.6 5.6l1.4 1.4 M17 17l1.4 1.4 M5.6 18.4l1.4-1.4 M17 7l1.4-1.4" }
        }
    }
}

#[component]
fn MoonIcon() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" }
        }
    }
}
