//! Re-encrypt every at-rest secret under the current key (BUNYIP-483).
//!
//! Run by the `bunyip-api reencrypt-secrets` subcommand (operator-controlled, so
//! a backup can be taken first) and by the admin key-rotation endpoints. The
//! pass covers EVERY column encrypted with [`AppKeySet`]:
//!
//! | table          | columns                                                     |
//! |----------------|-------------------------------------------------------------|
//! | `user_totp`    | `encrypted_secret` / `nonce` / `key_version`                |
//! | `user_totp`    | `pending_*` (BUNYIP-355 staged re-key)                      |
//! | `stripe_config`| `secret_key`, `webhook_secret` (+ nonces)                   |
//! | `email_config` | `smtp_password` (+ nonce)                                    |
//!
//! Idempotent: [`AppKeySet::rewrite`] returns `None` for a value already on the
//! current key and version, so a second run rewrites nothing. A value that no
//! key in the set can decrypt is reported and left untouched, never cleared.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::repositories::{EmailConfigRepository, StripeConfigRepository, TotpRepository};
use crate::services::AppKeySet;

/// What one pass did, per secret store.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReencryptSummary {
    /// Values rewritten under the current key.
    pub rewritten: u64,
    /// Values already on the current key (skipped).
    pub already_current: u64,
    /// Values no key in the set could decrypt, left untouched.
    pub undecryptable: Vec<String>,
}

impl ReencryptSummary {
    fn merge(&mut self, other: ReencryptSummary) {
        self.rewritten += other.rewritten;
        self.already_current += other.already_current;
        self.undecryptable.extend(other.undecryptable);
    }
}

impl std::fmt::Display for ReencryptSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} rewritten, {} already current, {} undecryptable",
            self.rewritten,
            self.already_current,
            self.undecryptable.len()
        )
    }
}

/// Re-encrypt the TOTP secrets (active and BUNYIP-355 pending).
pub async fn reencrypt_totp(pool: &PgPool, keys: &AppKeySet) -> Result<ReencryptSummary, AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        Vec<u8>,
        Vec<u8>,
        i16,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i16>,
    )> = sqlx::query_as(
        "SELECT id, encrypted_secret, nonce, key_version, \
         pending_encrypted_secret, pending_nonce, pending_key_version FROM user_totp",
    )
    .fetch_all(pool)
    .await?;

    let mut summary = ReencryptSummary::default();

    for (id, ciphertext, nonce, key_version, pending_ct, pending_nonce, pending_version) in rows {
        match keys.rewrite(&ciphertext, &nonce, key_version) {
            Ok(Some((ct, n, version))) => {
                TotpRepository::update_encryption(pool, id, &ct, &n, version).await?;
                summary.rewritten += 1;
            }
            Ok(None) => summary.already_current += 1,
            Err(_) => summary
                .undecryptable
                .push(format!("user_totp {id} (active secret)")),
        }

        // The staged re-key is encrypted under the same set; a NULL column
        // triple simply means no re-key is in flight.
        if let (Some(ct), Some(n), Some(version)) = (pending_ct, pending_nonce, pending_version) {
            match keys.rewrite(&ct, &n, version) {
                Ok(Some((new_ct, new_nonce, new_version))) => {
                    TotpRepository::update_pending_encryption(
                        pool,
                        id,
                        &new_ct,
                        &new_nonce,
                        new_version,
                    )
                    .await?;
                    summary.rewritten += 1;
                }
                Ok(None) => summary.already_current += 1,
                Err(_) => summary
                    .undecryptable
                    .push(format!("user_totp {id} (pending secret)")),
            }
        }
    }

    Ok(summary)
}

/// Re-encrypt the Stripe secret key and webhook signing secret.
pub async fn reencrypt_stripe(
    pool: &PgPool,
    keys: &AppKeySet,
) -> Result<ReencryptSummary, AppError> {
    let db = StripeConfigRepository::get(pool).await?;
    let mut summary = ReencryptSummary::default();

    let mut secret_key = None;
    let mut webhook_secret = None;

    for (label, ciphertext, nonce, slot) in [
        (
            "secret_key",
            db.secret_key.as_deref(),
            db.secret_key_nonce.as_deref(),
            &mut secret_key,
        ),
        (
            "webhook_secret",
            db.webhook_secret.as_deref(),
            db.webhook_secret_nonce.as_deref(),
            &mut webhook_secret,
        ),
    ] {
        let (Some(ciphertext), Some(nonce)) = (ciphertext, nonce) else {
            continue;
        };
        match keys.rewrite(ciphertext, nonce, db.key_version) {
            Ok(Some((ct, n, _))) => {
                *slot = Some((ct, n));
                summary.rewritten += 1;
            }
            Ok(None) => summary.already_current += 1,
            Err(_) => summary.undecryptable.push(format!("stripe_config {label}")),
        }
    }

    // Stamp the current version whenever anything was rewritten. A row whose
    // secrets are all already current keeps its version untouched.
    if summary.rewritten > 0 {
        StripeConfigRepository::update_secret_encryption(
            pool,
            secret_key.as_ref().map(|(ct, _)| ct.clone()),
            secret_key.as_ref().map(|(_, n)| n.clone()),
            webhook_secret.as_ref().map(|(ct, _)| ct.clone()),
            webhook_secret.as_ref().map(|(_, n)| n.clone()),
            keys.current_version,
        )
        .await?;
    }

    Ok(summary)
}

/// Re-encrypt the SMTP password on the `email_config` row.
pub async fn reencrypt_email(
    pool: &PgPool,
    keys: &AppKeySet,
) -> Result<ReencryptSummary, AppError> {
    let row = EmailConfigRepository::get(pool).await?;
    let mut summary = ReencryptSummary::default();

    let (Some(ciphertext), Some(nonce)) = (&row.smtp_password, &row.smtp_password_nonce) else {
        return Ok(summary);
    };

    match keys.rewrite(ciphertext, nonce, row.key_version) {
        Ok(Some((ct, n, version))) => {
            EmailConfigRepository::update_password_encryption(pool, &ct, &n, version).await?;
            summary.rewritten += 1;
        }
        Ok(None) => summary.already_current += 1,
        Err(_) => summary
            .undecryptable
            .push("email_config smtp_password".to_string()),
    }

    Ok(summary)
}

/// Run the whole pass: TOTP secrets, Stripe secrets and the SMTP password.
pub async fn reencrypt_all(pool: &PgPool, keys: &AppKeySet) -> Result<ReencryptSummary, AppError> {
    let mut summary = reencrypt_totp(pool, keys).await?;
    summary.merge(reencrypt_stripe(pool, keys).await?);
    summary.merge(reencrypt_email(pool, keys).await?);
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_merge_accumulates_every_store() {
        let mut a = ReencryptSummary {
            rewritten: 2,
            already_current: 1,
            undecryptable: vec!["user_totp x".into()],
        };
        a.merge(ReencryptSummary {
            rewritten: 1,
            already_current: 3,
            undecryptable: vec!["email_config smtp_password".into()],
        });

        assert_eq!(a.rewritten, 3);
        assert_eq!(a.already_current, 4);
        assert_eq!(a.undecryptable.len(), 2);
        assert_eq!(
            a.to_string(),
            "3 rewritten, 4 already current, 2 undecryptable"
        );
    }
}
