use crate::models::*;
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

pub type SharedMockStore = Arc<RwLock<MockStore>>;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("seed file not found: {0}")]
    Missing(String),
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Default)]
pub struct MockStore {
    pub users: Vec<User>,
    pub orgs: Vec<Org>,
    pub memberships: Vec<Membership>,
    pub invitations: Vec<Invitation>,
    pub tier_config: Vec<TierConfig>,
    pub subscriptions: Vec<Subscription>,
    pub oidc_clients: Vec<OidcClient>,
    pub audit_logs: Vec<AuditLog>,
    pub feedback: Vec<Feedback>,
    pub trusted_devices: Vec<TrustedDevice>,
}

impl MockStore {
    /// Load the in-memory store from a seeds directory containing one JSON file per collection.
    pub fn load_from_dir(seeds_dir: impl AsRef<Path>) -> Result<Self, LoadError> {
        let dir = seeds_dir.as_ref();
        info!(seeds_dir = %dir.display(), "loading mock seeds");
        Ok(Self {
            users: load_json(dir, "users.json")?,
            orgs: load_json(dir, "orgs.json")?,
            memberships: load_json(dir, "memberships.json")?,
            invitations: load_json(dir, "invitations.json")?,
            tier_config: load_json(dir, "tier_config.json")?,
            subscriptions: load_json(dir, "subscriptions.json")?,
            oidc_clients: load_json(dir, "oidc_clients.json")?,
            audit_logs: load_json(dir, "audit_logs.json")?,
            feedback: load_json(dir, "feedback.json")?,
            trusted_devices: Vec::new(),
        })
    }

    pub fn into_shared(self) -> SharedMockStore {
        Arc::new(RwLock::new(self))
    }

    // --- queries used by handlers ---

    pub fn find_user_by_email(&self, email: &str) -> Option<User> {
        self.users
            .iter()
            .find(|u| u.email.eq_ignore_ascii_case(email) && u.deleted_at.is_none())
            .cloned()
    }

    pub fn find_user(&self, id: Uuid) -> Option<User> {
        self.users.iter().find(|u| u.id == id).cloned()
    }

    pub fn memberships_for_user(&self, user_id: Uuid) -> Vec<Membership> {
        self.memberships
            .iter()
            .filter(|m| m.user_id == user_id)
            .cloned()
            .collect()
    }

    pub fn orgs_for_user(&self, user_id: Uuid) -> Vec<(Org, MembershipRole)> {
        self.memberships
            .iter()
            .filter(|m| m.user_id == user_id)
            .filter_map(|m| {
                self.orgs
                    .iter()
                    .find(|o| o.id == m.org_id)
                    .map(|o| (o.clone(), m.role))
            })
            .collect()
    }

    pub fn org_by_slug(&self, slug: &str) -> Option<Org> {
        self.orgs.iter().find(|o| o.slug == slug).cloned()
    }

    pub fn subscription_for_org(&self, org_id: Uuid) -> Option<Subscription> {
        self.subscriptions
            .iter()
            .find(|s| s.org_id == org_id)
            .cloned()
    }

    pub fn email_taken(&self, email: &str) -> bool {
        self.users
            .iter()
            .any(|u| u.email.eq_ignore_ascii_case(email) && u.deleted_at.is_none())
    }

    /// Inserts a new user (verified-on-create false) and returns the new row.
    pub fn create_user(&mut self, email: String, name: String, mfa_enabled: bool) -> User {
        let user = User {
            id: Uuid::new_v4(),
            email,
            name,
            role: UserRole::Member,
            email_verified_at: None,
            lifetime_member: false,
            mfa_enabled,
            created_at: chrono::Utc::now(),
            deleted_at: None,
        };
        self.users.push(user.clone());
        user
    }

    pub fn create_org(&mut self, slug: String, name: String, owner_user_id: Uuid) -> Org {
        let org = Org {
            id: Uuid::new_v4(),
            slug,
            name,
            owner_user_id,
            stripe_customer_id: None,
            created_at: chrono::Utc::now(),
        };
        self.orgs.push(org.clone());
        self.memberships.push(Membership {
            org_id: org.id,
            user_id: owner_user_id,
            role: MembershipRole::Owner,
            created_at: chrono::Utc::now(),
        });
        org
    }

    pub fn verify_user_email(&mut self, user_id: Uuid) -> bool {
        if let Some(u) = self.users.iter_mut().find(|u| u.id == user_id) {
            u.email_verified_at = Some(chrono::Utc::now());
            true
        } else {
            false
        }
    }

    pub fn log_audit(&mut self, entry: AuditLog) {
        self.audit_logs.push(entry);
    }

    pub fn members_of_org(&self, org_id: Uuid) -> Vec<(User, MembershipRole)> {
        self.memberships
            .iter()
            .filter(|m| m.org_id == org_id)
            .filter_map(|m| {
                self.users
                    .iter()
                    .find(|u| u.id == m.user_id)
                    .map(|u| (u.clone(), m.role))
            })
            .collect()
    }

    pub fn role_in_org(&self, user_id: Uuid, org_id: Uuid) -> Option<MembershipRole> {
        self.memberships
            .iter()
            .find(|m| m.user_id == user_id && m.org_id == org_id)
            .map(|m| m.role)
    }

    pub fn invitations_for_org(&self, org_id: Uuid) -> Vec<Invitation> {
        self.invitations
            .iter()
            .filter(|i| i.org_id == org_id && i.accepted_at.is_none())
            .cloned()
            .collect()
    }

    pub fn invitation_by_token(&self, token: &str) -> Option<Invitation> {
        self.invitations.iter().find(|i| i.token == token).cloned()
    }

    pub fn create_invitation(
        &mut self,
        org_id: Uuid,
        email: String,
        role: MembershipRole,
        invited_by: Uuid,
    ) -> Invitation {
        let token = format!("inv_{}", Uuid::new_v4().simple());
        let inv = Invitation {
            id: Uuid::new_v4(),
            org_id,
            email,
            role,
            token,
            invited_by_user_id: invited_by,
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
            accepted_at: None,
        };
        self.invitations.push(inv.clone());
        inv
    }

    pub fn delete_invitation(&mut self, org_id: Uuid, invite_id: Uuid) -> bool {
        let before = self.invitations.len();
        self.invitations
            .retain(|i| !(i.org_id == org_id && i.id == invite_id));
        self.invitations.len() != before
    }

    pub fn accept_invitation(
        &mut self,
        token: &str,
        accepting_user_id: Uuid,
    ) -> Option<Invitation> {
        let inv_idx = self
            .invitations
            .iter()
            .position(|i| i.token == token && i.accepted_at.is_none())?;
        let inv = self.invitations[inv_idx].clone();
        if inv.expires_at < chrono::Utc::now() {
            return None;
        }
        self.invitations[inv_idx].accepted_at = Some(chrono::Utc::now());
        // Avoid duplicate memberships if the user is already in the org.
        if self.role_in_org(accepting_user_id, inv.org_id).is_none() {
            self.memberships.push(Membership {
                org_id: inv.org_id,
                user_id: accepting_user_id,
                role: inv.role,
                created_at: chrono::Utc::now(),
            });
        }
        Some(inv)
    }

    pub fn remove_member(&mut self, org_id: Uuid, user_id: Uuid) -> bool {
        let before = self.memberships.len();
        self.memberships
            .retain(|m| !(m.org_id == org_id && m.user_id == user_id));
        self.memberships.len() != before
    }

    pub fn change_member_role(
        &mut self,
        org_id: Uuid,
        user_id: Uuid,
        role: MembershipRole,
    ) -> bool {
        if let Some(m) = self
            .memberships
            .iter_mut()
            .find(|m| m.org_id == org_id && m.user_id == user_id)
        {
            m.role = role;
            true
        } else {
            false
        }
    }
}

fn load_json<T: serde::de::DeserializeOwned>(dir: &Path, filename: &str) -> Result<T, LoadError> {
    let path = dir.join(filename);
    if !path.exists() {
        return Err(LoadError::Missing(path.display().to_string()));
    }
    let bytes = std::fs::read(&path).map_err(|source| LoadError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| LoadError::Parse {
        path: path.display().to_string(),
        source,
    })
}
