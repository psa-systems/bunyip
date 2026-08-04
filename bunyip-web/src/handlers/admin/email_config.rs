//! Admin panel: Email / SMTP config (BUNYIP-351).

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{
    AdminApplication, AdminAuditLog, AdminErrorLog, AdminFeedbackDetail, AdminIpBan,
    AdminRateLimit, AdminRateLimitConfig, AdminUser, AppRestoreStatus, ApplicationGroup,
    FeedbackAttachmentMeta, FeedbackStatus, RestoreReport, User, UserEntitlement,
};
use crate::auth::AuthCtx;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{relative_time, urlenc};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{badge, button_class, error_box, icon, success_box, toggle_switch};
use crate::web::{redirect, redirect_cookies, AppState};

use super::{pager, title_case};

pub(super) fn email_settings_content(
    cfg: Option<&crate::api::types::EmailConfigResponse>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Email" } p class="mt-2 text-muted-foreground" { "Configure the SMTP relay for transactional email. Changes apply immediately without a restart." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load email config." },
                // BUNYIP-415: two-column block layout. The SMTP transport
                // settings and the sender/notification settings sit in
                // side-by-side blocks (one column below lg), inside one form so
                // a single Save persists everything.
                Some(e) => div class="space-y-6" {
                    form method="post" action="/admin/email" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "SMTP Connection",
                            Some(&format!("Source: {}. Leave a field blank to keep the existing value.", e.source)),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "Sending" }
                                        select name="enabled" class=(dashboard_input()) {
                                            option value="true" selected[e.enabled] { "Enabled" }
                                            option value="false" selected[!e.enabled] { "Disabled" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP host" } input name="smtp_host" value=(e.smtp_host) placeholder="smtp.example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP port" } input name="smtp_port" type="number" min="1" max="65535" value=(e.smtp_port) class=(dashboard_input()); }
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "TLS mode" }
                                        select name="smtp_tls" class=(dashboard_input()) {
                                            option value="implicit" selected[e.smtp_tls == "implicit"] { "Implicit (port 465)" }
                                            option value="starttls" selected[e.smtp_tls == "starttls"] { "STARTTLS (port 587)" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP username" } input name="smtp_username" value=(e.smtp_username) autocomplete="off" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP password" } input name="smtp_password" type="password" autocomplete="new-password" placeholder=(if e.has_smtp_password { "••••••••" } else { "Not set" }) class=(dashboard_input()); p class="text-xs text-muted-foreground" {
                                        // BUNYIP-432: the placeholder is a fixed-length mask driven only
                                        // by has_smtp_password; the real password (and its length) never
                                        // reaches the browser. Leave blank to keep the current one.
                                        @if e.has_smtp_password { "A password is set (stored encrypted). Leave blank to keep it, or type a new one to replace it." } @else { "No password set. Stored encrypted when you save one." }
                                    } }
                                }
                            },
                        ),
                        admin_block(
                            "Sender & Notifications",
                            Some("Who transactional mail comes from, and where operational notices go."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" { label class="text-sm font-medium" { "From email" } input name="from_email" type="email" value=(e.from_email) placeholder="noreply@example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "From name" } input name="from_name" value=(e.from_name) class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Admin notification emails" } input name="admin_notification_emails" value=(e.admin_notification_emails.join(", ")) placeholder="ops@example.com, alerts@example.com" class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Comma-separated recipients for operational notices." } }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    // BUNYIP-433: Test connection lives in its own form so it
                    // submits no fields - it always tests the SAVED settings,
                    // never the unsaved edits in the form above.
                    form method="post" action="/admin/email/test" class="flex flex-wrap items-center gap-3 border-t border-border/50 pt-4" {
                        button type="submit" class=(button_class("outline", "default", "")) { (icon("mail", "mr-2 h-4 w-4")) "Test connection" }
                        p class="text-xs text-muted-foreground" { "Opens a connection to the saved SMTP server and signs in, without sending an email. Save changes first to test them." }
                    }
                },
            }
        }
    }
}
