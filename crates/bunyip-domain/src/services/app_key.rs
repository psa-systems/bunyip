//! The single at-rest encryption key set (BUNYIP-483).
//!
//! One `APP_ENCRYPTION_KEY` protects every secret bunyip stores encrypted in
//! Postgres: TOTP secrets (`user_totp`), the Stripe credentials
//! (`stripe_config`) and the SMTP password (`email_config`). It replaces the
//! two retired per-consumer key families, which were the same primitive twice
//! over with names that no longer described what they protected.
//!
//! dunite-core's [`EncryptionKeySet`] models exactly ONE previous key, which is
//! enough for a version-numbered rotation but not for the consolidation: rows
//! written under BOTH retired keys must stay readable at once. Rather than
//! widening the shared kernel type for a bunyip-only migration, [`AppKeySet`]
//! wraps it here and accepts a LIST of previous keys
//! (`APP_ENCRYPTION_KEY_PREV`, comma-separated). Encryption still uses the
//! kernel's AES-256-GCM path, so ciphertexts are unchanged.
//!
//! The list is the only transitional part: once every deployment has run
//! `reencrypt-secrets`, BUNYIP-491 drops this wrapper for the kernel type.

use crate::errors::AppError;
use crate::services::encryption::{decrypt_with_key, EncryptionKeySet};

/// Current at-rest key plus every previous key still needed to read old rows.
#[derive(Clone)]
pub struct AppKeySet {
    /// The key every new write is encrypted under.
    pub current: [u8; 32],
    /// Version stamped on rows written under `current`.
    pub current_version: i16,
    /// Keys retired but still in use by rows that have not been re-encrypted:
    /// the two legacy key families during the consolidation window (BUNYIP-491
    /// removes that case), and the prior key during an ordinary rotation.
    pub previous: Vec<[u8; 32]>,
}

impl AppKeySet {
    /// Encrypt with the current key. Returns `(ciphertext, nonce, key_version)`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, i16), AppError> {
        EncryptionKeySet {
            current: self.current,
            current_version: self.current_version,
            previous: None,
        }
        .encrypt(plaintext)
    }

    /// Decrypt with whichever key in the set works.
    ///
    /// `key_version` only orders the attempts (a row stamped with an older
    /// version is likely on a previous key): with several previous keys the
    /// stored version no longer identifies one, so every key is tried before
    /// the read is called a failure.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_version: i16,
    ) -> Result<Vec<u8>, AppError> {
        let mut keys: Vec<&[u8; 32]> = Vec::with_capacity(self.previous.len() + 1);
        if key_version == self.current_version {
            keys.push(&self.current);
            keys.extend(self.previous.iter());
        } else {
            keys.extend(self.previous.iter());
            keys.push(&self.current);
        }

        for key in keys {
            if let Ok(plaintext) = decrypt_with_key(key, ciphertext, nonce) {
                return Ok(plaintext);
            }
        }

        Err(AppError::internal(format!(
            "Decryption failed with the current key and all {} previous key(s)",
            self.previous.len()
        )))
    }

    /// True when the stored value is already on the current key AND version, so
    /// a re-encrypt pass can skip it.
    pub fn is_current(&self, ciphertext: &[u8], nonce: &[u8], key_version: i16) -> bool {
        key_version == self.current_version
            && decrypt_with_key(&self.current, ciphertext, nonce).is_ok()
    }

    /// Re-encrypt one stored value under the current key.
    ///
    /// Returns `None` when the value is already current, which is what makes the
    /// re-encrypt pass idempotent: a second run finds nothing to rewrite.
    #[allow(clippy::type_complexity)]
    pub fn rewrite(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_version: i16,
    ) -> Result<Option<(Vec<u8>, Vec<u8>, i16)>, AppError> {
        if self.is_current(ciphertext, nonce, key_version) {
            return Ok(None);
        }
        let plaintext = self.decrypt(ciphertext, nonce, key_version)?;
        Ok(Some(self.encrypt(&plaintext)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two retired key families: the TOTP one, and the one that guarded
    // `stripe_config` and `email_config` alike despite its Stripe-only name.
    const LEGACY_TOTP_KEY: [u8; 32] = [0xA1; 32];
    const LEGACY_CONFIG_KEY: [u8; 32] = [0xB2; 32];
    const APP_KEY: [u8; 32] = [0xC3; 32];

    fn legacy(key: [u8; 32]) -> AppKeySet {
        AppKeySet {
            current: key,
            current_version: 1,
            previous: Vec::new(),
        }
    }

    /// The consolidation window: `APP_ENCRYPTION_KEY` is new, and both retired
    /// key families are listed in `APP_ENCRYPTION_KEY_PREV`.
    fn transitional() -> AppKeySet {
        AppKeySet {
            current: APP_KEY,
            current_version: 2,
            previous: vec![LEGACY_TOTP_KEY, LEGACY_CONFIG_KEY],
        }
    }

    #[test]
    fn roundtrip_under_the_current_key() {
        let ks = legacy(APP_KEY);
        let (ct, nonce, version) = ks.encrypt(b"secret").unwrap();
        assert_eq!(version, 1);
        assert_eq!(ks.decrypt(&ct, &nonce, version).unwrap(), b"secret");
    }

    /// BUNYIP-483: a database populated under the two old keys stays readable
    /// through the one consolidated key set.
    #[test]
    fn legacy_totp_and_stripe_rows_both_decrypt_under_the_new_key_set() {
        // Written by the old TotpService, under the retired TOTP key.
        let (totp_ct, totp_nonce, totp_ver) =
            legacy(LEGACY_TOTP_KEY).encrypt(b"totp-secret").unwrap();
        // Written by the old Stripe/email path, under the retired config key.
        let (stripe_ct, stripe_nonce, stripe_ver) =
            legacy(LEGACY_CONFIG_KEY).encrypt(b"sk_live_abc").unwrap();

        let app = transitional();
        assert_eq!(
            app.decrypt(&totp_ct, &totp_nonce, totp_ver).unwrap(),
            b"totp-secret"
        );
        assert_eq!(
            app.decrypt(&stripe_ct, &stripe_nonce, stripe_ver).unwrap(),
            b"sk_live_abc"
        );
    }

    #[test]
    fn decrypt_fails_when_no_key_in_the_set_matches() {
        let (ct, nonce, ver) = legacy([0xEE; 32]).encrypt(b"orphan").unwrap();
        assert!(transitional().decrypt(&ct, &nonce, ver).is_err());
    }

    #[test]
    fn is_current_only_for_the_current_key_and_version() {
        let app = transitional();
        let (ct, nonce, ver) = app.encrypt(b"fresh").unwrap();
        assert!(app.is_current(&ct, &nonce, ver));

        let (old_ct, old_nonce, old_ver) = legacy(LEGACY_TOTP_KEY).encrypt(b"old").unwrap();
        assert!(!app.is_current(&old_ct, &old_nonce, old_ver));
    }

    /// BUNYIP-483: the re-encrypt pass is idempotent. The first pass rewrites a
    /// legacy row; the second finds nothing to do and the value still reads.
    #[test]
    fn rewrite_is_idempotent() {
        let app = transitional();
        let (ct, nonce, ver) = legacy(LEGACY_CONFIG_KEY).encrypt(b"whsec_xyz").unwrap();

        let (new_ct, new_nonce, new_ver) = app.rewrite(&ct, &nonce, ver).unwrap().unwrap();
        assert_eq!(new_ver, app.current_version);
        assert_eq!(
            app.decrypt(&new_ct, &new_nonce, new_ver).unwrap(),
            b"whsec_xyz"
        );

        assert!(app.rewrite(&new_ct, &new_nonce, new_ver).unwrap().is_none());
        assert_eq!(
            app.decrypt(&new_ct, &new_nonce, new_ver).unwrap(),
            b"whsec_xyz"
        );
    }

    #[test]
    fn rewrite_reports_an_undecryptable_row_instead_of_dropping_it() {
        let (ct, nonce, ver) = legacy([0xEE; 32]).encrypt(b"orphan").unwrap();
        assert!(transitional().rewrite(&ct, &nonce, ver).is_err());
    }

    #[test]
    fn ordinary_rotation_still_reads_the_single_previous_key() {
        let (ct, nonce, _) = legacy(LEGACY_CONFIG_KEY).encrypt(b"rotating").unwrap();
        let rotated = AppKeySet {
            current: APP_KEY,
            current_version: 2,
            previous: vec![LEGACY_CONFIG_KEY],
        };
        assert_eq!(rotated.decrypt(&ct, &nonce, 1).unwrap(), b"rotating");
    }
}
