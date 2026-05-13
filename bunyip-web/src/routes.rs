use dioxus::prelude::*;

use crate::pages::{
    active_tenant::ActiveTenantPage,
    admin::AdminFeedbackPage,
    audit_logs::AuditLogsPage,
    auth::{
        ForgotPasswordPage, LoginPage, LoginTotpPage, MagicLinkPage, ResetPasswordPage,
        SignupCompletePage, SignupPage, VerifyEmailPage,
    },
    auth_callback::AuthCallbackPage,
    billing::OrgBillingPage,
    dashboard::DashboardPage,
    errors::NotFoundPage,
    feedback::FeedbackPage,
    invitations::AcceptInvitationPage,
    invite_create::InviteCreatePage,
    invite_list::InviteListPage,
    landing::LandingPage,
    orgs::{OrgListPage, OrgMembersPage},
    placeholder::PlaceholderPage,
    pricing::PricingPage,
    profile::ProfilePage,
    security::SecurityPage,
    sessions::SessionsPage,
    settings::SettingsPage,
    user_management::UserManagementPage,
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

    #[route("/reset-password/:token")]
    ResetPasswordPage { token: String },

    #[route("/signup/:token")]
    SignupCompletePage { token: String },

    #[route("/auth/callback")]
    AuthCallbackPage {},

    // Authenticated
    #[route("/dashboard")]
    DashboardPage {},

    #[route("/settings")]
    SettingsPage {},

    #[route("/settings/active-tenant")]
    ActiveTenantPage {},

    #[route("/settings/profile")]
    ProfilePage {},

    #[route("/settings/security")]
    SecurityPage {},

    #[route("/settings/sessions")]
    SessionsPage {},

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

    #[route("/admin/users")]
    UserManagementPage {},

    #[route("/admin/users/invite")]
    InviteCreatePage {},

    #[route("/admin/users/invites")]
    InviteListPage {},

    #[route("/admin/audit-logs")]
    AuditLogsPage {},

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
