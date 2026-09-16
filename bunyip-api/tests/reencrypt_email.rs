//! BUNYIP-689: `reencrypt_email` rewrites both `smtp_password` and
//! `imap_password` on the `email_config` row, each under its own version.
//!
//! Env-gated like `applications_catalog.rs`: it needs a throwaway Postgres to
//! migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse `RLS_TEST_DATABASE_URL`)
//! to a database this test may migrate; unset skips the test.

use bunyip_api::repositories::EmailConfigRepository;
use bunyip_api::services::AppKeySet;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

#[tokio::test]
async fn reencrypt_email_rewrites_both_passwords_under_the_new_key() {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping reencrypt_email test"
        );
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    // Save the row's current password columns and key_version so the test can
    // restore them, since email_config is a singleton (id = 1) shared with
    // every other test that migrates this database.
    let saved = sqlx::query(
        "SELECT smtp_password, smtp_password_nonce, imap_password, imap_password_nonce, \
         key_version FROM email_config WHERE id = 1",
    )
    .fetch_one(&pool)
    .await
    .expect("read email_config row");
    let saved_smtp_password: Option<Vec<u8>> = saved.get("smtp_password");
    let saved_smtp_password_nonce: Option<Vec<u8>> = saved.get("smtp_password_nonce");
    let saved_imap_password: Option<Vec<u8>> = saved.get("imap_password");
    let saved_imap_password_nonce: Option<Vec<u8>> = saved.get("imap_password_nonce");
    let saved_key_version: i16 = saved.get("key_version");

    let key_a: [u8; 32] = [0xA1; 32];
    let key_b: [u8; 32] = [0xB2; 32];

    let write_set = AppKeySet {
        current: key_a,
        current_version: 1,
        previous: Vec::new(),
    };
    let (smtp_ct, smtp_nonce, smtp_version) = write_set.encrypt(b"smtp-secret").unwrap();
    let (imap_ct, imap_nonce, imap_version) = write_set.encrypt(b"imap-secret").unwrap();
    assert_eq!(smtp_version, imap_version);

    sqlx::query(
        "UPDATE email_config SET smtp_password = $1, smtp_password_nonce = $2, \
         imap_password = $3, imap_password_nonce = $4, key_version = $5 WHERE id = 1",
    )
    .bind(&smtp_ct)
    .bind(&smtp_nonce)
    .bind(&imap_ct)
    .bind(&imap_nonce)
    .bind(smtp_version)
    .execute(&pool)
    .await
    .expect("write test ciphertext under key A");

    let rotate_set = AppKeySet {
        current: key_b,
        current_version: 2,
        previous: vec![key_a],
    };

    let summary = bunyip_api::reencrypt::reencrypt_email(&pool, &rotate_set)
        .await
        .expect("reencrypt_email");

    assert_eq!(summary.rewritten, 2);
    assert_eq!(summary.already_current, 0);
    assert!(summary.undecryptable.is_empty());

    let row = EmailConfigRepository::get(&pool)
        .await
        .expect("read email_config row after reencrypt");

    let read_only_b = AppKeySet {
        current: key_b,
        current_version: 2,
        previous: Vec::new(),
    };

    let decrypted_smtp = read_only_b
        .decrypt(
            row.smtp_password.as_deref().unwrap(),
            row.smtp_password_nonce.as_deref().unwrap(),
            row.key_version,
        )
        .expect("decrypt smtp_password with key B alone");
    assert_eq!(decrypted_smtp, b"smtp-secret");

    let decrypted_imap = read_only_b
        .decrypt(
            row.imap_password.as_deref().unwrap(),
            row.imap_password_nonce.as_deref().unwrap(),
            row.key_version,
        )
        .expect("decrypt imap_password with key B alone");
    assert_eq!(decrypted_imap, b"imap-secret");

    // Restore the row so this test leaves no trace for others sharing the
    // database.
    sqlx::query(
        "UPDATE email_config SET smtp_password = $1, smtp_password_nonce = $2, \
         imap_password = $3, imap_password_nonce = $4, key_version = $5 WHERE id = 1",
    )
    .bind(&saved_smtp_password)
    .bind(&saved_smtp_password_nonce)
    .bind(&saved_imap_password)
    .bind(&saved_imap_password_nonce)
    .bind(saved_key_version)
    .execute(&pool)
    .await
    .expect("restore email_config row");
}
