use dioxus::prelude::*;

use crate::pages::{
    admin::AdminFeedbackPage,
    auth::{ForgotPasswordPage, LoginPage, LoginTotpPage, MagicLinkPage, ResetPasswordPage, SignupPage, VerifyEmailPage},
    billing::OrgBillingPage,
    dashboard::DashboardPage,
    errors::NotFoundPage,
    feedback::FeedbackPage,
    invitations::AcceptInvitationPage,
    landing::LandingPage,
    orgs::{OrgListPage, OrgMembersPage},
    placeholder::PlaceholderPage,
    pricing::PricingPage,
};

#[derive(Routable, Clone, Debug, PartialEq)]
#[rustfmt::skip]
pub enum Route {
    // Public
    #[route("/")]
    LandingPage {},

    #[route("/pricing")]
    PricingPage {},

    #[route("/feedback")]
    FeedbackPage {},

    // Auth
    #[route("/signup")]
    SignupPage {},

    #[route("/login")]
    LoginPage {},

    #[route("/login/totp")]
    LoginTotpPage {},

    #[route("/login/magic-link")]
    MagicLinkPage {},

    #[route("/verify-email")]
    VerifyEmailPage {},

    #[route("/forgot-password")]
    ForgotPasswordPage {},

    #[route("/reset-password")]
    ResetPasswordPage {},

    // Authenticated
    #[route("/dashboard")]
    DashboardPage {},

    #[route("/settings/orgs")]
    OrgListPage {},

    #[route("/settings/orgs/:slug/members")]
    OrgMembersPage { slug: String },

    #[route("/settings/orgs/:slug/billing")]
    OrgBillingPage { slug: String },

    #[route("/invitations/accept")]
    AcceptInvitationPage {},

    #[route("/admin/feedback")]
    AdminFeedbackPage {},

    // Catch-all placeholder for the many settings / admin / billing / etc. routes
    // that Phase 5-6 will wire up.
    #[route("/:..segments")]
    PlaceholderPage { segments: Vec<String> },
}

impl Default for Route {
    fn default() -> Self {
        Route::LandingPage {}
    }
}

#[allow(dead_code)]
fn _not_found_marker() -> Element {
    NotFoundPage()
}
