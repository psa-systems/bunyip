//! Audit log and admin notification models

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Audit action types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    UserLogin,
    UserLogout,
    UserRegistered,
    MagicLinkRequested,
    MagicLinkUsed,
    PasswordResetRequested,
    PasswordResetCompleted,
    PasswordChanged,
    MembershipCreated,
    MembershipCanceled,
    MembershipReactivated,
    PaymentSucceeded,
    PaymentFailed,
    GracePeriodStarted,
    GracePeriodEnded,
    AdminUserImpersonated,
    AdminPasswordReset,
    AdminMembershipGranted,
    AdminMembershipRevoked,
    EmailChangeRequested,
    EmailChangeCompleted,
    AdminUserDeactivated,
    AdminUserActivated,
    ApplicationMaintenanceToggled,
    TwoFactorEnabled,
    TwoFactorDisabled,
    TwoFactorVerified,
    TwoFactorRecoveryCodeUsed,
    TwoFactorRecoveryCodesRegenerated,
    EmailVerificationRequested,
    EmailVerified,
    FeedbackSubmitted,
    FeedbackResponded,
    FeedbackDeleted,
    FeedbackRestored,
    ApplicationCreated,
    ApplicationDeleted,
    AdminUserRoleChanged,
    AdminUserDeleted,
    ApplicationUpdated,
    AdminInviteCreated,
    AdminInviteAccepted,
    AdminInviteRevoked,
    AdminStripeConfigUpdated,
    AdminTierConfigUpdated,
    AdminKeyRotation,
    UserAccountDeleted,
    DownloadRequested,
    DownloadCompleted,
    DownloadDeniedMembership,
    DownloadDeniedRateLimit,
    DownloadFailedUpstream,
    OciLoginSucceeded,
    OciLoginFailed,
    OciPullRequested,
    OciPullCompleted,
    OciPullFailedUpstream,
    OciPullDeniedRateLimit,
    OciPullDeniedScope,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::UserLogin => "user_login",
            AuditAction::UserLogout => "user_logout",
            AuditAction::UserRegistered => "user_registered",
            AuditAction::MagicLinkRequested => "magic_link_requested",
            AuditAction::MagicLinkUsed => "magic_link_used",
            AuditAction::PasswordResetRequested => "password_reset_requested",
            AuditAction::PasswordResetCompleted => "password_reset_completed",
            AuditAction::PasswordChanged => "password_changed",
            AuditAction::MembershipCreated => "membership_created",
            AuditAction::MembershipCanceled => "membership_canceled",
            AuditAction::MembershipReactivated => "membership_reactivated",
            AuditAction::PaymentSucceeded => "payment_succeeded",
            AuditAction::PaymentFailed => "payment_failed",
            AuditAction::GracePeriodStarted => "grace_period_started",
            AuditAction::GracePeriodEnded => "grace_period_ended",
            AuditAction::AdminUserImpersonated => "admin_user_impersonated",
            AuditAction::AdminPasswordReset => "admin_password_reset",
            AuditAction::AdminMembershipGranted => "admin_membership_granted",
            AuditAction::AdminMembershipRevoked => "admin_membership_revoked",
            AuditAction::EmailChangeRequested => "email_change_requested",
            AuditAction::EmailChangeCompleted => "email_change_completed",
            AuditAction::AdminUserDeactivated => "admin_user_deactivated",
            AuditAction::AdminUserActivated => "admin_user_activated",
            AuditAction::ApplicationMaintenanceToggled => "application_maintenance_toggled",
            AuditAction::TwoFactorEnabled => "two_factor_enabled",
            AuditAction::TwoFactorDisabled => "two_factor_disabled",
            AuditAction::TwoFactorVerified => "two_factor_verified",
            AuditAction::TwoFactorRecoveryCodeUsed => "two_factor_recovery_code_used",
            AuditAction::TwoFactorRecoveryCodesRegenerated => {
                "two_factor_recovery_codes_regenerated"
            }
            AuditAction::EmailVerificationRequested => "email_verification_requested",
            AuditAction::EmailVerified => "email_verified",
            AuditAction::FeedbackSubmitted => "feedback_submitted",
            AuditAction::FeedbackResponded => "feedback_responded",
            AuditAction::FeedbackDeleted => "feedback_deleted",
            AuditAction::FeedbackRestored => "feedback_restored",
            AuditAction::ApplicationCreated => "application_created",
            AuditAction::ApplicationDeleted => "application_deleted",
            AuditAction::AdminUserRoleChanged => "admin_user_role_changed",
            AuditAction::AdminUserDeleted => "admin_user_deleted",
            AuditAction::ApplicationUpdated => "application_updated",
            AuditAction::AdminInviteCreated => "admin_invite_created",
            AuditAction::AdminInviteAccepted => "admin_invite_accepted",
            AuditAction::AdminInviteRevoked => "admin_invite_revoked",
            AuditAction::AdminStripeConfigUpdated => "admin_stripe_config_updated",
            AuditAction::AdminTierConfigUpdated => "admin_tier_config_updated",
            AuditAction::AdminKeyRotation => "admin_key_rotation",
            AuditAction::UserAccountDeleted => "user_account_deleted",
            AuditAction::DownloadRequested => "download_requested",
            AuditAction::DownloadCompleted => "download_completed",
            AuditAction::DownloadDeniedMembership => "download_denied_membership",
            AuditAction::DownloadDeniedRateLimit => "download_denied_rate_limit",
            AuditAction::DownloadFailedUpstream => "download_failed_upstream",
            AuditAction::OciLoginSucceeded => "oci_login_succeeded",
            AuditAction::OciLoginFailed => "oci_login_failed",
            AuditAction::OciPullRequested => "oci_pull_requested",
            AuditAction::OciPullCompleted => "oci_pull_completed",
            AuditAction::OciPullFailedUpstream => "oci_pull_failed_upstream",
            AuditAction::OciPullDeniedRateLimit => "oci_pull_denied_rate_limit",
            AuditAction::OciPullDeniedScope => "oci_pull_denied_scope",
        }
    }

    pub fn is_admin_action(&self) -> bool {
        matches!(
            self,
            AuditAction::AdminUserImpersonated
                | AuditAction::AdminPasswordReset
                | AuditAction::AdminMembershipGranted
                | AuditAction::AdminMembershipRevoked
                | AuditAction::AdminUserDeactivated
                | AuditAction::AdminUserActivated
                | AuditAction::ApplicationMaintenanceToggled
                | AuditAction::ApplicationCreated
                | AuditAction::ApplicationDeleted
                | AuditAction::ApplicationUpdated
                | AuditAction::AdminUserRoleChanged
                | AuditAction::AdminUserDeleted
                | AuditAction::FeedbackResponded
                | AuditAction::FeedbackDeleted
                | AuditAction::FeedbackRestored
                | AuditAction::AdminInviteCreated
                | AuditAction::AdminInviteAccepted
                | AuditAction::AdminInviteRevoked
                | AuditAction::AdminStripeConfigUpdated
                | AuditAction::AdminTierConfigUpdated
                | AuditAction::AdminKeyRotation
        )
    }
}

/// Audit severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl AuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditSeverity::Info => "info",
            AuditSeverity::Warning => "warning",
            AuditSeverity::Error => "error",
            AuditSeverity::Critical => "critical",
        }
    }
}

impl Default for AuditSeverity {
    fn default() -> Self {
        AuditSeverity::Info
    }
}

/// Audit log database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    pub actor_ip_address: Option<IpNetwork>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub old_values: Option<JsonValue>,
    pub new_values: Option<JsonValue>,
    pub metadata: Option<JsonValue>,
    pub is_admin_action: bool,
    pub severity: String,
    pub created_at: DateTime<Utc>,
}

/// Data for creating a new audit log entry
#[derive(Debug, Clone)]
pub struct CreateAuditLog {
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    pub actor_ip_address: Option<IpNetwork>,
    pub action: AuditAction,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub old_values: Option<JsonValue>,
    pub new_values: Option<JsonValue>,
    pub metadata: Option<JsonValue>,
    pub severity: AuditSeverity,
}

impl CreateAuditLog {
    pub fn new(action: AuditAction) -> Self {
        Self {
            actor_id: None,
            actor_email: None,
            actor_role: None,
            actor_ip_address: None,
            action,
            resource_type: None,
            resource_id: None,
            old_values: None,
            new_values: None,
            metadata: None,
            severity: AuditSeverity::Info,
        }
    }

    pub fn with_actor(mut self, id: Uuid, email: &str, role: &str) -> Self {
        self.actor_id = Some(id);
        self.actor_email = Some(email.to_string());
        self.actor_role = Some(role.to_string());
        self
    }

    pub fn with_ip(mut self, ip: Option<IpNetwork>) -> Self {
        self.actor_ip_address = ip;
        self
    }

    pub fn with_resource(mut self, resource_type: &str, resource_id: Uuid) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self.resource_id = Some(resource_id);
        self
    }

    pub fn with_old_values(mut self, old_values: JsonValue) -> Self {
        self.old_values = Some(old_values);
        self
    }

    pub fn with_new_values(mut self, new_values: JsonValue) -> Self {
        self.new_values = Some(new_values);
        self
    }

    pub fn with_metadata(mut self, metadata: JsonValue) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }
}

/// Admin notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    NewSignup,
    PaymentFailed,
    MembershipCanceled,
    GracePeriodExpiring,
    SystemAlert,
    NewFeedback,
}

impl NotificationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationType::NewSignup => "new_signup",
            NotificationType::PaymentFailed => "payment_failed",
            NotificationType::MembershipCanceled => "membership_canceled",
            NotificationType::GracePeriodExpiring => "grace_period_expiring",
            NotificationType::SystemAlert => "system_alert",
            NotificationType::NewFeedback => "new_feedback",
        }
    }
}

/// Admin notification database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminNotification {
    pub id: Uuid,
    #[sqlx(rename = "type")]
    pub notification_type: String,
    pub title: String,
    pub message: String,
    pub metadata: Option<JsonValue>,
    pub user_id: Option<Uuid>,
    pub is_read: bool,
    pub read_by: Option<Uuid>,
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Data for creating a new admin notification
#[derive(Debug, Clone)]
pub struct CreateAdminNotification {
    pub notification_type: NotificationType,
    pub title: String,
    pub message: String,
    pub metadata: Option<JsonValue>,
    pub user_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- AuditAction --

    #[test]
    fn audit_action_as_str_covers_all_variants() {
        // Spot-check a few
        assert_eq!(AuditAction::UserLogin.as_str(), "user_login");
        assert_eq!(AuditAction::UserRegistered.as_str(), "user_registered");
        assert_eq!(
            AuditAction::AdminUserImpersonated.as_str(),
            "admin_user_impersonated"
        );
        assert_eq!(
            AuditAction::FeedbackSubmitted.as_str(),
            "feedback_submitted"
        );
        assert_eq!(
            AuditAction::ApplicationDeleted.as_str(),
            "application_deleted"
        );
        assert_eq!(
            AuditAction::AdminUserRoleChanged.as_str(),
            "admin_user_role_changed"
        );
        assert_eq!(AuditAction::AdminUserDeleted.as_str(), "admin_user_deleted");
        assert_eq!(
            AuditAction::ApplicationUpdated.as_str(),
            "application_updated"
        );
    }

    #[test]
    fn audit_action_download_variants() {
        assert_eq!(
            AuditAction::DownloadRequested.as_str(),
            "download_requested"
        );
        assert_eq!(
            AuditAction::DownloadCompleted.as_str(),
            "download_completed"
        );
        assert_eq!(
            AuditAction::DownloadDeniedMembership.as_str(),
            "download_denied_membership"
        );
        assert_eq!(
            AuditAction::DownloadDeniedRateLimit.as_str(),
            "download_denied_rate_limit"
        );
        assert_eq!(
            AuditAction::DownloadFailedUpstream.as_str(),
            "download_failed_upstream"
        );

        assert!(!AuditAction::DownloadRequested.is_admin_action());
        assert!(!AuditAction::DownloadCompleted.is_admin_action());
    }

    #[test]
    fn audit_action_oci_variants() {
        assert_eq!(
            AuditAction::OciLoginSucceeded.as_str(),
            "oci_login_succeeded"
        );
        assert_eq!(AuditAction::OciLoginFailed.as_str(), "oci_login_failed");
        assert_eq!(AuditAction::OciPullRequested.as_str(), "oci_pull_requested");
        assert_eq!(AuditAction::OciPullCompleted.as_str(), "oci_pull_completed");
        assert_eq!(
            AuditAction::OciPullFailedUpstream.as_str(),
            "oci_pull_failed_upstream"
        );
        assert_eq!(
            AuditAction::OciPullDeniedRateLimit.as_str(),
            "oci_pull_denied_rate_limit"
        );
        assert_eq!(
            AuditAction::OciPullDeniedScope.as_str(),
            "oci_pull_denied_scope"
        );

        assert!(!AuditAction::OciPullRequested.is_admin_action());
        assert!(!AuditAction::OciLoginFailed.is_admin_action());
        assert!(!AuditAction::OciPullDeniedScope.is_admin_action());
    }

    #[test]
    fn audit_action_is_admin_action() {
        assert!(AuditAction::AdminUserImpersonated.is_admin_action());
        assert!(AuditAction::AdminPasswordReset.is_admin_action());
        assert!(AuditAction::AdminMembershipGranted.is_admin_action());
        assert!(AuditAction::FeedbackResponded.is_admin_action());
        assert!(AuditAction::ApplicationCreated.is_admin_action());
        assert!(AuditAction::ApplicationDeleted.is_admin_action());
        assert!(AuditAction::ApplicationUpdated.is_admin_action());
        assert!(AuditAction::AdminUserRoleChanged.is_admin_action());
        assert!(AuditAction::AdminUserDeleted.is_admin_action());

        assert!(!AuditAction::UserLogin.is_admin_action());
        assert!(!AuditAction::UserRegistered.is_admin_action());
        assert!(!AuditAction::PasswordChanged.is_admin_action());
        assert!(!AuditAction::FeedbackSubmitted.is_admin_action());
    }

    // -- AuditSeverity --

    #[test]
    fn audit_severity_as_str() {
        assert_eq!(AuditSeverity::Info.as_str(), "info");
        assert_eq!(AuditSeverity::Warning.as_str(), "warning");
        assert_eq!(AuditSeverity::Error.as_str(), "error");
        assert_eq!(AuditSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn audit_severity_default() {
        let s = AuditSeverity::default();
        assert_eq!(s.as_str(), "info");
    }

    // -- NotificationType --

    #[test]
    fn notification_type_as_str() {
        assert_eq!(NotificationType::NewSignup.as_str(), "new_signup");
        assert_eq!(NotificationType::PaymentFailed.as_str(), "payment_failed");
        assert_eq!(NotificationType::NewFeedback.as_str(), "new_feedback");
    }

    // -- CreateAuditLog builder --

    #[test]
    fn create_audit_log_builder() {
        let user_id = Uuid::new_v4();
        let log = CreateAuditLog::new(AuditAction::UserLogin)
            .with_actor(user_id, "test@example.com", "subscriber")
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({"key": "value"}))
            .with_severity(AuditSeverity::Warning);

        assert_eq!(log.actor_id, Some(user_id));
        assert_eq!(log.actor_email.as_deref(), Some("test@example.com"));
        assert_eq!(log.actor_role.as_deref(), Some("subscriber"));
        assert_eq!(log.resource_type.as_deref(), Some("user"));
        assert_eq!(log.resource_id, Some(user_id));
        assert!(log.metadata.is_some());
        assert_eq!(log.severity.as_str(), "warning");
    }

    #[test]
    fn create_audit_log_with_old_new_values() {
        let log = CreateAuditLog::new(AuditAction::AdminUserRoleChanged)
            .with_old_values(serde_json::json!({"role": "subscriber"}))
            .with_new_values(serde_json::json!({"role": "admin"}));

        assert_eq!(
            log.old_values,
            Some(serde_json::json!({"role": "subscriber"}))
        );
        assert_eq!(log.new_values, Some(serde_json::json!({"role": "admin"})));
    }

    #[test]
    fn create_audit_log_defaults() {
        let log = CreateAuditLog::new(AuditAction::UserLogout);
        assert!(log.actor_id.is_none());
        assert!(log.actor_email.is_none());
        assert!(log.resource_type.is_none());
        assert!(log.metadata.is_none());
        assert_eq!(log.severity.as_str(), "info");
    }
}
