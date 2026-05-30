//! TOTP two-factor authentication service

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::errors::AppError;
use crate::repositories::TotpRepository;
use crate::services::encryption::EncryptionKeySet;

/// Response from beginning 2FA setup
pub struct TotpSetupInfo {
    pub otpauth_uri: String,
    pub secret: String,
}

/// TOTP service for managing two-factor authentication
pub struct TotpService {
    key_set: EncryptionKeySet,
    issuer: String,
    pool: PgPool,
}

impl TotpService {
    pub fn new(key_set: EncryptionKeySet, issuer: String, pool: PgPool) -> Self {
        Self {
            key_set,
            issuer,
            pool,
        }
    }

    /// Returns a reference to the encryption key set (used by admin rotation endpoints).
    pub fn key_set(&self) -> &EncryptionKeySet {
        &self.key_set
    }

    /// Begin 2FA setup: generate a TOTP secret and return the otpauth URI
    pub async fn begin_setup(&self, user_id: Uuid, email: &str) -> Result<TotpSetupInfo, AppError> {
        let secret = Secret::generate_secret();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| AppError::internal(format!("Failed to generate TOTP secret: {}", e)))?;

        let totp = self.build_totp(&secret_bytes, email)?;
        let otpauth_uri = totp.get_url();
        let secret_base32 = data_encoding::BASE32_NOPAD.encode(&secret_bytes);

        // Encrypt and store the secret
        let (encrypted, nonce, key_version) = self.key_set.encrypt(&secret_bytes)?;
        TotpRepository::upsert_totp(&self.pool, user_id, &encrypted, &nonce, key_version).await?;

        Ok(TotpSetupInfo {
            otpauth_uri,
            secret: secret_base32,
        })
    }

    /// Confirm 2FA setup by verifying a TOTP code, then generate recovery codes
    pub async fn confirm_setup(&self, user_id: Uuid, code: &str) -> Result<Vec<String>, AppError> {
        let totp_record = TotpRepository::find_by_user_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("TOTP configuration"))?;

        if totp_record.verified {
            return Err(AppError::conflict("2FA is already enabled"));
        }

        // Decrypt secret and verify code
        let secret = self.key_set.decrypt(
            &totp_record.encrypted_secret,
            &totp_record.nonce,
            totp_record.key_version,
        )?;
        if !self.check_code(&secret, code)? {
            return Err(AppError::validation("code", "Invalid verification code"));
        }

        // Mark as verified
        TotpRepository::mark_verified(&self.pool, user_id).await?;

        // Generate recovery codes
        let codes = self.generate_and_store_recovery_codes(user_id).await?;
        Ok(codes)
    }

    /// Verify a TOTP code for login
    pub async fn verify_code(&self, user_id: Uuid, code: &str) -> Result<bool, AppError> {
        let totp_record = TotpRepository::find_by_user_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("TOTP configuration"))?;

        if !totp_record.verified {
            return Ok(false);
        }

        let secret = self.key_set.decrypt(
            &totp_record.encrypted_secret,
            &totp_record.nonce,
            totp_record.key_version,
        )?;
        self.check_code(&secret, code)
    }

    /// Verify a recovery code (marks it as used if valid).
    /// Supports both legacy unsalted SHA-256 hashes and new Argon2id hashes.
    pub async fn verify_recovery_code(&self, user_id: Uuid, code: &str) -> Result<bool, AppError> {
        let normalized = code.to_uppercase().replace('-', "");

        let unused_codes =
            TotpRepository::find_all_unused_recovery_codes(&self.pool, user_id).await?;

        for recovery_code in unused_codes {
            if Self::verify_code_against_hash(&normalized, &recovery_code.code_hash)? {
                TotpRepository::mark_recovery_code_used(&self.pool, recovery_code.id).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Regenerate recovery codes (requires 2FA to be enabled)
    pub async fn regenerate_recovery_codes(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let totp_record = TotpRepository::find_by_user_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("TOTP configuration"))?;

        if !totp_record.verified {
            return Err(AppError::validation("2fa", "2FA is not enabled"));
        }

        self.generate_and_store_recovery_codes(user_id).await
    }

    /// Disable 2FA for a user
    pub async fn disable(&self, user_id: Uuid) -> Result<(), AppError> {
        TotpRepository::delete_by_user_id(&self.pool, user_id).await?;
        Ok(())
    }

    /// Check if 2FA is enabled for a user
    pub async fn is_enabled(&self, user_id: Uuid) -> Result<bool, AppError> {
        match TotpRepository::find_by_user_id(&self.pool, user_id).await? {
            Some(record) => Ok(record.verified),
            None => Ok(false),
        }
    }

    /// Get the count of remaining unused recovery codes
    pub async fn recovery_codes_remaining(&self, user_id: Uuid) -> Result<i64, AppError> {
        let count = TotpRepository::count_unused_recovery_codes(&self.pool, user_id).await?;
        Ok(count)
    }

    // --- Internal helpers ---

    fn build_totp(&self, secret: &[u8], account_name: &str) -> Result<TOTP, AppError> {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_vec(),
            Some(self.issuer.clone()),
            account_name.to_string(),
        )
        .map_err(|e| AppError::internal(format!("Failed to create TOTP: {}", e)))
    }

    fn check_code(&self, secret: &[u8], code: &str) -> Result<bool, AppError> {
        // Allow spaced format (e.g. "123 456" → "123456")
        let code = code.replace(' ', "");
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_vec(),
            Some(self.issuer.clone()),
            String::new(),
        )
        .map_err(|e| {
            AppError::internal(format!("Failed to create TOTP for verification: {}", e))
        })?;

        totp.check_current(&code)
            .map_err(|e| AppError::internal(format!("System time error: {}", e)))
    }

    async fn generate_and_store_recovery_codes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let mut codes = Vec::with_capacity(8);
        let mut hashes = Vec::with_capacity(8);

        for _ in 0..8 {
            let code = Self::generate_recovery_code();
            let normalized = code.replace('-', "");
            let hash = Self::hash_code_argon2(&normalized)?;
            codes.push(code);
            hashes.push(hash);
        }

        TotpRepository::insert_recovery_codes(&self.pool, user_id, &hashes).await?;

        Ok(codes)
    }

    fn generate_recovery_code() -> String {
        let mut bytes = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut bytes);
        let hex = hex::encode(bytes).to_uppercase();
        format!("{}-{}", &hex[..4], &hex[4..])
    }

    /// Legacy unsalted SHA-256 hash (kept for verifying existing codes)
    fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Salted Argon2id hash for new recovery codes
    fn hash_code_argon2(code: &str) -> Result<String, AppError> {
        let params = Params::new(19 * 1024, 2, 1, None)
            .map_err(|e| AppError::internal(format!("Argon2 params error: {}", e)))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2
            .hash_password(code.as_bytes(), &salt)
            .map_err(|e| AppError::internal(format!("Recovery code hashing failed: {}", e)))?;

        Ok(hash.to_string())
    }

    /// Detect legacy unsalted SHA-256 hashes (64 hex chars)
    fn is_legacy_hash(hash: &str) -> bool {
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Verify a code against a stored hash, supporting both legacy SHA-256 and Argon2id
    fn verify_code_against_hash(code: &str, stored_hash: &str) -> Result<bool, AppError> {
        if Self::is_legacy_hash(stored_hash) {
            let computed = Self::hash_code(code);
            Ok(computed == stored_hash)
        } else {
            let parsed = PasswordHash::new(stored_hash)
                .map_err(|e| AppError::internal(format!("Invalid hash format: {}", e)))?;
            let params = Params::new(19 * 1024, 2, 1, None)
                .map_err(|e| AppError::internal(format!("Argon2 params error: {}", e)))?;
            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            Ok(argon2.verify_password(code.as_bytes(), &parsed).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::encryption::EncryptionKeySet;

    fn test_key_set() -> EncryptionKeySet {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(b"test-encrypt-key");
        key[16..].copy_from_slice(b"0123456789abcdef");
        EncryptionKeySet {
            current: key,
            current_version: 1,
            previous: None,
        }
    }

    // -- encrypt/decrypt round-trip --

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let ks = test_key_set();
        let secret = b"my-totp-secret-data";

        let (encrypted, nonce, version) = ks.encrypt(secret).unwrap();
        assert_eq!(version, 1);

        let decrypted = ks.decrypt(&encrypted, &nonce, 1).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let ks = test_key_set();
        let (encrypted, nonce, _) = ks.encrypt(b"secret-data").unwrap();

        let wrong_ks = EncryptionKeySet {
            current: [0xFFu8; 32],
            current_version: 1,
            previous: None,
        };
        assert!(wrong_ks.decrypt(&encrypted, &nonce, 1).is_err());
    }

    // -- generate_recovery_code --

    #[test]
    fn recovery_code_format() {
        let code = TotpService::generate_recovery_code();
        // Format: XXXX-XXXX (uppercase hex)
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert!(code[..4].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(code[5..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn recovery_codes_are_unique() {
        let code1 = TotpService::generate_recovery_code();
        let code2 = TotpService::generate_recovery_code();
        // Extremely unlikely to collide
        assert_ne!(code1, code2);
    }

    // -- hash_code --

    #[test]
    fn hash_code_deterministic() {
        let hash1 = TotpService::hash_code("ABCD1234");
        let hash2 = TotpService::hash_code("ABCD1234");
        assert_eq!(hash1, hash2);
        // SHA256 = 64 hex chars
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn hash_code_different_inputs() {
        let hash1 = TotpService::hash_code("CODE1");
        let hash2 = TotpService::hash_code("CODE2");
        assert_ne!(hash1, hash2);
    }

    // -- key rotation scenarios --

    fn rotated_key() -> [u8; 32] {
        [0xDD; 32]
    }

    #[test]
    fn decrypt_totp_secret_with_previous_key() {
        let ks_v1 = test_key_set();
        let totp_secret = b"JBSWY3DPEHPK3PXP"; // typical TOTP base32 secret

        // Encrypt with v1
        let (ct, nonce, _) = ks_v1.encrypt(totp_secret).unwrap();

        // Rotate: new key is current, old key is previous
        let ks_v2 = EncryptionKeySet {
            current: rotated_key(),
            current_version: 2,
            previous: Some(ks_v1.current),
        };

        // Should decrypt via fallback to previous key
        let decrypted = ks_v2.decrypt(&ct, &nonce, 1).unwrap();
        assert_eq!(decrypted, totp_secret);
    }

    #[test]
    fn reencrypt_totp_secret_roundtrip() {
        let ks_v1 = test_key_set();
        let totp_secret = b"JBSWY3DPEHPK3PXP";

        // Encrypt with v1
        let (ct_old, nonce_old, _) = ks_v1.encrypt(totp_secret).unwrap();

        // Rotate to v2
        let ks_v2 = EncryptionKeySet {
            current: rotated_key(),
            current_version: 2,
            previous: Some(ks_v1.current),
        };

        // Simulate re-encryption: decrypt old, encrypt new
        let plain = ks_v2.decrypt(&ct_old, &nonce_old, 1).unwrap();
        let (ct_new, nonce_new, ver_new) = ks_v2.encrypt(&plain).unwrap();
        assert_eq!(ver_new, 2);

        // After removing old key, new ciphertext still decrypts
        let ks_v2_only = EncryptionKeySet {
            current: rotated_key(),
            current_version: 2,
            previous: None,
        };
        let final_plain = ks_v2_only.decrypt(&ct_new, &nonce_new, 2).unwrap();
        assert_eq!(final_plain, totp_secret);
    }

    #[test]
    fn new_totp_setup_uses_current_version() {
        // After rotation, new encryptions should use the current version
        let ks_v2 = EncryptionKeySet {
            current: rotated_key(),
            current_version: 2,
            previous: Some(test_key_set().current),
        };

        let (_, _, version) = ks_v2.encrypt(b"new-totp-secret").unwrap();
        assert_eq!(version, 2);
    }

    #[test]
    fn key_set_accessor_returns_reference() {
        // Verify TotpService.key_set() is accessible for rotation endpoints.
        // We can't construct a full TotpService without PgPool, but we can
        // verify the EncryptionKeySet type is correct through the test helpers.
        let ks = test_key_set();
        assert_eq!(ks.current_version, 1);
        assert!(ks.previous.is_none());
        assert!(!ks.needs_reencrypt(1));
        assert!(ks.needs_reencrypt(0));
    }

    // -- argon2 recovery code hashing --

    #[test]
    fn hash_code_argon2_produces_phc_string() {
        let hash = TotpService::hash_code_argon2("ABCD1234").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn hash_code_argon2_unique_salts() {
        let hash1 = TotpService::hash_code_argon2("ABCD1234").unwrap();
        let hash2 = TotpService::hash_code_argon2("ABCD1234").unwrap();
        // Same input, different salts => different hashes
        assert_ne!(hash1, hash2);
    }

    // -- is_legacy_hash --

    #[test]
    fn is_legacy_hash_detects_sha256() {
        let sha256 = TotpService::hash_code("ABCD1234");
        assert!(TotpService::is_legacy_hash(&sha256));
    }

    #[test]
    fn is_legacy_hash_rejects_argon2() {
        let argon2_hash = TotpService::hash_code_argon2("ABCD1234").unwrap();
        assert!(!TotpService::is_legacy_hash(&argon2_hash));
    }

    // -- verify_code_against_hash --

    #[test]
    fn verify_against_legacy_sha256_hash() {
        let code = "ABCD1234";
        let hash = TotpService::hash_code(code);
        assert!(TotpService::verify_code_against_hash(code, &hash).unwrap());
        assert!(!TotpService::verify_code_against_hash("WRONG123", &hash).unwrap());
    }

    #[test]
    fn verify_against_argon2_hash() {
        let code = "ABCD1234";
        let hash = TotpService::hash_code_argon2(code).unwrap();
        assert!(TotpService::verify_code_against_hash(code, &hash).unwrap());
        assert!(!TotpService::verify_code_against_hash("WRONG123", &hash).unwrap());
    }
}
