//! BUNYIP-542: the `SECRETS_STORAGE` contract, enforced mechanically.
//!
//! The behavioural half (the enforcement table, the fail-closed Infisical path,
//! the 409) is unit-tested in `bunyip_api::secrets`. What lives here is the
//! half a unit test cannot hold: that the DELETED precedence chain stays
//! deleted, and that every read and write site of a governed secret goes through
//! the one store layer. Each of these is a one-line edit away from silently
//! coming back, which is exactly why they are grep-asserted.

use std::path::{Path, PathBuf};

use bunyip_domain::config::{env_spec, EnvClass, GovernedSecret, SecretsStorage};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bunyip-api sits one level below the workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(workspace_root().join(relative))
        .unwrap_or_else(|e| panic!("readable source {relative}: {e}"))
}

/// The part of a source file that is NOT its `#[cfg(test)]` module.
fn production_code(source: &str) -> String {
    match source.find("#[cfg(test)]") {
        Some(idx) => source[..idx].to_string(),
        None => source.to_string(),
    }
}

/// `SECRETS_STORAGE` is required in EVERY environment, with the legal values in
/// its remedy: an unset value must stop the boot, not fall back to a guess.
#[test]
fn secrets_storage_is_required_everywhere_and_names_its_legal_values() {
    let spec = env_spec("SECRETS_STORAGE").expect("classified in ENV_INVENTORY");
    assert_eq!(spec.class, EnvClass::Required);
    for value in ["environment", "database", "infisical"] {
        assert!(
            spec.remedy.contains(value),
            "the remedy must name the legal value {value}: {}",
            spec.remedy
        );
        assert_eq!(
            SecretsStorage::parse(value).map(|s| s.as_str()),
            Some(value)
        );
    }
    assert!(SecretsStorage::parse("db").is_none());
    assert!(SecretsStorage::parse("").is_none());
    assert!(SecretsStorage::LEGAL_VALUES.contains("infisical"));
}

/// The three-level precedence chain is GONE. `EmailConfig::from_env` used to
/// read `SMTP_PASSWORD` into a slot that `from_db_row` fell back to and that a
/// conditional Infisical fetch topped up "only when empty"; each of those three
/// reads is asserted absent.
#[test]
fn the_smtp_password_precedence_chain_stays_deleted() {
    let config = production_code(&read("crates/bunyip-domain/src/config.rs"));
    assert!(
        !config.contains("secret_env(\"SMTP_PASSWORD\")"),
        "EmailConfig must not read SMTP_PASSWORD itself: the governed-secret \
         resolution owns it (BUNYIP-542)"
    );

    let main = production_code(&read("bunyip-api/src/main.rs"));
    assert!(
        !main.contains("fetch_secret("),
        "main.rs must not call Infisical directly; the store layer \
         (bunyip_api::secrets) owns every store read (BUNYIP-542)"
    );
    assert!(
        !main.contains("smtp_password.is_empty()"),
        "the `fill the slot only when it is empty` fetch is the precedence chain \
         this issue removed (BUNYIP-542)"
    );
}

/// Every governed secret is read from the environment file-backed only. A plain
/// `STRIPE_SECRET_KEY=sk_live_...` in a compose `environment:` block is the
/// exposure BUNYIP-38 removed, so `secret_env` (which falls back to the plain
/// variable) must not be how a governed secret arrives.
#[test]
fn the_environment_store_is_file_backed_only() {
    let config = read("crates/bunyip-domain/src/config.rs");
    let reader = config
        .split("pub fn read_environment(self) -> Option<String> {")
        .nth(1)
        .expect("GovernedSecret::read_environment exists");
    let body = reader.split('}').next().unwrap_or(reader);
    assert!(
        body.contains("secret_file_env"),
        "the environment store must read {{NAME}}_FILE only: {body}"
    );
    assert!(
        !body.contains("secret_env("),
        "secret_env falls back to the plain variable, which is the exposure \
         BUNYIP-38 removed: {body}"
    );

    let file_reader = config
        .split("fn secret_file_env(name: &str) -> Option<String> {")
        .nth(1)
        .expect("secret_file_env exists");
    let file_body = file_reader.split("\n}").next().unwrap_or(file_reader);
    assert!(
        file_body.contains("{name}_FILE"),
        "the reader resolves the _FILE variable: {file_body}"
    );
    assert!(
        !file_body.contains("env::var(name)"),
        "the plain variable must not be a fallback: {file_body}"
    );
}

/// The admin save paths write through the store layer, never straight to the
/// ciphertext columns, and gate that write on the declared store. Without this
/// an `infisical`-mode save would silently keep writing the database.
#[test]
fn admin_saves_go_through_the_declared_store() {
    for (relative, handler) in [
        ("bunyip-api/src/handlers/admin.rs", "update_email_config"),
        ("bunyip-api/src/handlers/admin.rs", "update_stripe_config"),
        (
            "bunyip-api/src/handlers/admin_stripe.rs",
            "create_stripe_webhook",
        ),
    ] {
        let source = read(relative);
        let marker = format!("\npub async fn {handler}(");
        let body = source
            .split(&marker)
            .nth(1)
            .unwrap_or_else(|| panic!("{handler} exists in {relative}"))
            .split("\n}")
            .next()
            .unwrap_or_default()
            .to_string();
        assert!(
            body.contains("config.secrets_storage") || body.contains("storage"),
            "{handler} must resolve the declared store before writing a secret"
        );
        assert!(
            body.contains("read_only_store_error"),
            "{handler} must answer 409 when the declared store is not writable"
        );
        assert!(
            body.contains("crate::secrets::write_secret")
                || body.contains("SecretsStorage::Database"),
            "{handler} must write through the store layer, not straight to the \
             ciphertext columns"
        );
    }
}

/// `stripe_config_from_db_model` and `StripeConfigResponse::from_db` decrypt the
/// row's own ciphertext columns, so they are correct ONLY when the database is
/// the declared store. They stay as the database-store form (and as decryption
/// test coverage), but nothing that serves a request or boots the api may call
/// them: that call is the DB-only read the store declaration replaced.
#[test]
fn the_database_only_stripe_readers_have_no_request_or_boot_callers() {
    for relative in [
        "bunyip-api/src/main.rs",
        "bunyip-api/src/handlers/admin.rs",
        "bunyip-api/src/handlers/admin_stripe.rs",
    ] {
        let source = production_code(&read(relative));
        for reader in [
            "stripe_config_from_db_model(",
            "StripeConfigResponse::from_db(",
        ] {
            assert!(
                !source.contains(reader),
                "{relative} calls {reader}, which reads the database copy regardless of \
                 SECRETS_STORAGE. Use crate::secrets::stripe_runtime_config / read_secret \
                 (BUNYIP-542)."
            );
        }
    }
}

/// Every governed secret carries the operator-facing metadata the reports and
/// the runbook need: a name, the feature it gates, and a secret-file target for
/// `secrets-migrate --to environment`.
#[test]
fn every_governed_secret_is_fully_described() {
    assert_eq!(GovernedSecret::ALL.len(), 3);
    for secret in GovernedSecret::ALL {
        assert!(!secret.name().is_empty());
        assert!(
            secret.feature().len() > 20,
            "{} needs a feature sentence naming what stops working",
            secret.name()
        );
        assert!(!secret.secret_file().is_empty());
    }
    let names: Vec<&str> = GovernedSecret::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(
        names,
        [
            "SMTP_PASSWORD",
            "STRIPE_SECRET_KEY",
            "STRIPE_WEBHOOK_SECRET"
        ]
    );
}

/// `environment` is the one read-only store, and that is a property of the
/// store rather than a policy: a process cannot set a variable for its own next
/// boot, and the compose secret files are mounted read-only.
#[test]
fn only_the_environment_store_is_read_only() {
    assert!(!SecretsStorage::Environment.is_writable());
    assert!(SecretsStorage::Database.is_writable());
    assert!(SecretsStorage::Infisical.is_writable());
}

/// The reference compose file states the store with no default, and both dev
/// overlays default it to `database`, which is what dev has always used.
#[test]
fn compose_declares_the_store() {
    let production = read("compose.yml");
    assert!(
        production.contains("SECRETS_STORAGE: ${SECRETS_STORAGE:?"),
        "compose.yml must pass SECRETS_STORAGE with no default"
    );
    for overlay in ["compose.dev.yml", "compose.dev-sso.yml"] {
        assert!(
            read(overlay).contains("SECRETS_STORAGE: ${SECRETS_STORAGE:-database}"),
            "{overlay} must default SECRETS_STORAGE to database so `just dev` is unchanged"
        );
    }
}
