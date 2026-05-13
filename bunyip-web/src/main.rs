use dioxus::prelude::*;

mod api;
mod components;
mod pages;
mod routes;
mod stores;

use components::feedback::FeedbackLauncher;
use components::toast::ToastViewport;
use routes::Route;
use stores::auth::use_auth_provider;
use stores::toast::use_toast_provider;

const STYLES_CSS: Asset = asset!("/assets/styles.css");

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    use_toast_provider();
    use_auth_provider();

    rsx! {
        document::Stylesheet { href: STYLES_CSS }
        Router::<Route> {}
        FeedbackLauncher {}
        ToastViewport {}
    }
}
