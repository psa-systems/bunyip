//! BUNYIP-542: the governed-secret store layer.
//!
//! An integration secret used to live in whichever of three places happened to
//! be populated, resolved by a precedence chain nobody could see. Now one
//! required variable, `SECRETS_STORAGE`, declares the store, and only that store
//! is consulted. This module is where a governed secret is read from a store,
//! written to a store, and where the boot enforcement decides what a copy in the
//! wrong store means.
//!
//! Enforcement, per governed secret, at boot:
//!
//! | Situation                                       | Behaviour                                     |
//! |-------------------------------------------------|-----------------------------------------------|
//! | present in the declared store                    | use it                                        |
//! | absent everywhere                                | feature off, one `warn!`                      |
//! | absent from the declared store, present in another | fatal: `error!` naming `secrets-migrate`, exit 1 |
//! | present in the declared store AND in another     | boot, one `warn!` per duplicate naming `secrets-purge` |
//!
//! The last row is what keeps a later mode change honest: a stale copy in a
//! store nobody reads today becomes live the moment someone flips the mode.

use bunyip_domain::config::{Config, GovernedSecret, SecretsStorage};
use bunyip_domain::errors::AppError;
use bunyip_domain::models::stripe::{decrypt_secret, encrypt_secret};
use bunyip_domain::repositories::{EmailConfigRepository, StripeConfigRepository};
use bunyip_domain::services::{AppKeySet, InfisicalClient};
use sqlx::PgPool;
use tracing::{error, warn};

/// Whether a survey inspects the Infisical store.
///
/// `Skip` is the boot posture in `database` / `environment` mode: those modes
/// never contact Infisical, which is what keeps Infisical off the boot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfisicalProbe {
    /// Do not call Infisical at all.
    Skip,
    /// Inspect Infisical; a failure is recorded, not swallowed.
    Inspect,
}

/// One governed secret as every inspected store sees it.
#[derive(Debug, Clone)]
pub struct SecretSurvey {
    pub secret: GovernedSecret,
    /// Every inspected store that holds a value, in [`SecretsStorage::ALL`] order.
    pub holders: Vec<SecretsStorage>,
    /// The value held by the declared store, when it holds one. Never logged,
    /// never printed: it exists so a save and a migration can copy it.
    pub value: Option<String>,
}

impl SecretSurvey {
    /// Whether the declared store holds this secret.
    pub fn present_in(&self, storage: SecretsStorage) -> bool {
        self.holders.contains(&storage)
    }
}

/// Every governed secret, across every inspected store.
#[derive(Debug, Clone)]
pub struct Survey {
    /// The declared store this survey was taken against.
    pub storage: SecretsStorage,
    pub secrets: Vec<SecretSurvey>,
    /// Whether the Infisical store was inspected at all.
    pub infisical_inspected: bool,
    /// The Infisical failure, when the probe ran and could not complete. The
    /// store's contents are then unknown, which is a different fact from
    /// "the store is empty" and is reported as such.
    pub infisical_error: Option<String>,
}

impl Survey {
    /// One secret's row.
    pub fn get(&self, secret: GovernedSecret) -> &SecretSurvey {
        self.secrets
            .iter()
            .find(|row| row.secret == secret)
            .expect("every governed secret is surveyed")
    }

    /// The declared store's value for one secret.
    pub fn value(&self, secret: GovernedSecret) -> Option<&str> {
        self.get(secret).value.as_deref()
    }

    /// Whether every governed secret is present in `storage`. `secrets-purge`
    /// refuses to run unless this holds for the declared store, so a purge can
    /// never leave a deployment with no copy at all.
    pub fn complete_in(&self, storage: SecretsStorage) -> bool {
        self.secrets.iter().all(|row| row.present_in(storage))
    }
}

/// What the boot enforcement decides for one governed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The declared store holds it and no other inspected store does.
    Use,
    /// No inspected store holds it: the feature stays off.
    FeatureOff,
    /// The declared store is empty but another store holds it. Fatal: using the
    /// other store's copy would be exactly the silent precedence this removes,
    /// and ignoring it would disable a feature the operator plainly configured.
    Misplaced(Vec<SecretsStorage>),
    /// The declared store holds it, and so does another. Boots, but the stale
    /// copy becomes live on a later mode change, so it is named.
    Duplicated(Vec<SecretsStorage>),
}

/// The pure enforcement decision: which store was declared, which stores hold a
/// value. Kept free of IO so every cell of the table above is unit-tested.
pub fn classify(declared: SecretsStorage, holders: &[SecretsStorage]) -> Enforcement {
    let elsewhere: Vec<SecretsStorage> = holders
        .iter()
        .copied()
        .filter(|store| *store != declared)
        .collect();
    match (holders.contains(&declared), elsewhere.is_empty()) {
        (true, true) => Enforcement::Use,
        (true, false) => Enforcement::Duplicated(elsewhere),
        (false, true) => Enforcement::FeatureOff,
        (false, false) => Enforcement::Misplaced(elsewhere),
    }
}

/// Read every governed secret from every store this run is allowed to inspect.
///
/// The database read always runs (the pool is already open); the environment
/// read is free; Infisical is inspected only when `probe` says so, which is what
/// keeps `database` / `environment` mode off the network at boot.
pub async fn survey(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    probe: InfisicalProbe,
) -> Result<Survey, AppError> {
    let email_row = EmailConfigRepository::get(pool).await?;
    let stripe_row = StripeConfigRepository::get(pool).await?;

    let db_value = |secret: GovernedSecret| -> Option<String> {
        match secret {
            GovernedSecret::SmtpPassword => {
                bunyip_domain::config::EmailConfig::db_smtp_password(&email_row, key_set)
            }
            GovernedSecret::StripeSecretKey => decrypt_column(
                key_set,
                secret,
                stripe_row.secret_key.as_deref(),
                stripe_row.secret_key_nonce.as_deref(),
                stripe_row.key_version,
            ),
            GovernedSecret::StripeWebhookSecret => decrypt_column(
                key_set,
                secret,
                stripe_row.webhook_secret.as_deref(),
                stripe_row.webhook_secret_nonce.as_deref(),
                stripe_row.key_version,
            ),
        }
    };

    // One client, one login per secret read. Built only when the probe runs.
    let client = match probe {
        InfisicalProbe::Skip => None,
        InfisicalProbe::Inspect => InfisicalClient::from_settings(&config.infisical),
    };
    let mut infisical_error = match (probe, &client) {
        // Enabled but half-configured: the credentials are missing, so the store
        // cannot be inspected. Recorded rather than read as "empty".
        (InfisicalProbe::Inspect, None) => Some(
            "the Infisical client is not configured (INFISICAL_ADDRESS / INFISICAL_PROJECT_ID / \
             INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET)"
                .to_string(),
        ),
        _ => None,
    };

    let mut secrets = Vec::with_capacity(GovernedSecret::ALL.len());
    for secret in GovernedSecret::ALL {
        let database = db_value(secret);
        let environment = secret.read_environment();
        let infisical = match (&client, infisical_error.is_some()) {
            (Some(client), false) => match client.fetch_secret(secret.name()).await {
                Ok(value) => value,
                Err(e) => {
                    infisical_error = Some(e.to_string());
                    None
                }
            },
            _ => None,
        };

        let mut holders = Vec::new();
        for (store, value) in [
            (SecretsStorage::Environment, &environment),
            (SecretsStorage::Database, &database),
            (SecretsStorage::Infisical, &infisical),
        ] {
            if value.is_some() {
                holders.push(store);
            }
        }
        let value = match config.secrets_storage {
            SecretsStorage::Environment => environment,
            SecretsStorage::Database => database,
            SecretsStorage::Infisical => infisical,
        };
        secrets.push(SecretSurvey {
            secret,
            holders,
            value,
        });
    }

    Ok(Survey {
        storage: config.secrets_storage,
        secrets,
        infisical_inspected: probe == InfisicalProbe::Inspect && infisical_error.is_none(),
        infisical_error,
    })
}

/// Read ONE governed secret from the declared store.
///
/// The single-secret form of [`survey`], for request paths that need the live
/// value without inspecting every store. Same rule: only the declared store is
/// consulted, so an admin page can never show a value the running service does
/// not use.
pub async fn read_secret(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    secret: GovernedSecret,
) -> Result<Option<String>, AppError> {
    match config.secrets_storage {
        SecretsStorage::Environment => Ok(secret.read_environment()),
        SecretsStorage::Database => match secret {
            GovernedSecret::SmtpPassword => {
                let row = EmailConfigRepository::get(pool).await?;
                Ok(bunyip_domain::config::EmailConfig::db_smtp_password(
                    &row, key_set,
                ))
            }
            GovernedSecret::StripeSecretKey => {
                let row = StripeConfigRepository::get(pool).await?;
                Ok(decrypt_column(
                    key_set,
                    secret,
                    row.secret_key.as_deref(),
                    row.secret_key_nonce.as_deref(),
                    row.key_version,
                ))
            }
            GovernedSecret::StripeWebhookSecret => {
                let row = StripeConfigRepository::get(pool).await?;
                Ok(decrypt_column(
                    key_set,
                    secret,
                    row.webhook_secret.as_deref(),
                    row.webhook_secret_nonce.as_deref(),
                    row.key_version,
                ))
            }
        },
        SecretsStorage::Infisical => {
            let client = InfisicalClient::from_settings(&config.infisical)
                .ok_or_else(infisical_unconfigured_error)?;
            client.fetch_secret(secret.name()).await.map_err(|e| {
                error!(error = %e, secret = secret.name(), "failed to read the secret from Infisical");
                AppError::Upstream {
                    message: format!("Could not read {} from Infisical: {e}", secret.name()),
                }
            })
        }
    }
}

/// Rebuild the runtime Stripe config for a hot reload: the non-secret columns
/// from the `stripe_config` row, both secrets from the declared store.
///
/// This is what keeps a save in `infisical` mode reloading the same service the
/// `database` mode save does, with no DB write of the secrets.
pub async fn stripe_runtime_config(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    row: &bunyip_domain::models::stripe::StripeConfig,
) -> Result<bunyip_domain::services::StripeConfig, AppError> {
    let mut runtime = bunyip_domain::services::stripe_settings_from_db_model(row);
    let unconfigured = bunyip_domain::services::unconfigured_stripe_config();
    runtime.secret_key = read_secret(pool, config, key_set, GovernedSecret::StripeSecretKey)
        .await?
        .unwrap_or(unconfigured.secret_key);
    runtime.webhook_secret =
        read_secret(pool, config, key_set, GovernedSecret::StripeWebhookSecret)
            .await?
            .unwrap_or(unconfigured.webhook_secret);
    Ok(runtime)
}

/// Decrypt one `stripe_config` ciphertext column. A value no key in the set can
/// read is reported at `error` and treated as absent: the enforcement below then
/// says so out loud instead of quietly falling through to another store.
fn decrypt_column(
    key_set: &AppKeySet,
    secret: GovernedSecret,
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    key_version: i16,
) -> Option<String> {
    let (ciphertext, nonce) = (ciphertext?, nonce?);
    match decrypt_secret(key_set, ciphertext, nonce, key_version) {
        Ok(value) => Some(value),
        Err(e) => {
            error!(
                error = %e,
                secret = secret.name(),
                key_version,
                "the stored ciphertext does not decrypt with APP_ENCRYPTION_KEY or any \
                 APP_ENCRYPTION_KEY_PREV entry; treating the database store as holding no value \
                 for this secret"
            );
            None
        }
    }
}

/// The boot enforcement: apply [`classify`] to every governed secret, logging
/// each verdict. Returns the fatal reports, if any, so `main.rs` owns the exit.
///
/// The Infisical store of record being unreachable is fatal on its own in
/// `infisical` mode: the operator declared it as the store of record, and a
/// silent boot with payments and email disabled serves nobody.
pub fn enforce(survey: &Survey) -> Vec<String> {
    let declared = survey.storage;
    let mut fatal = Vec::new();

    if declared == SecretsStorage::Infisical {
        if let Some(cause) = &survey.infisical_error {
            fatal.push(format!(
                "SECRETS_STORAGE=infisical declares Infisical as the store of record, but it \
                 could not be read: {cause}. Fix the Infisical connection, or declare a store \
                 this deployment can reach."
            ));
            return fatal;
        }
    }

    for row in &survey.secrets {
        match classify(declared, &row.holders) {
            Enforcement::Use => {}
            Enforcement::FeatureOff => warn!(
                secret = row.secret.name(),
                secrets_storage = %declared,
                "{} is not set in the declared {declared} store, and no other store holds it: {}. \
                 Set it on the admin page, or with `bunyip-api secrets-migrate`.",
                row.secret.name(),
                row.secret.feature(),
            ),
            Enforcement::Misplaced(elsewhere) => fatal.push(format!(
                "{} is absent from the declared {declared} store but present in the {} store. \
                 bunyip will not silently use a store the deployment did not declare. Copy it \
                 with `bunyip-api secrets-migrate --to {declared}`, or set \
                 SECRETS_STORAGE to the store that holds it.",
                row.secret.name(),
                store_list(&elsewhere),
            )),
            Enforcement::Duplicated(elsewhere) => {
                for store in elsewhere {
                    warn!(
                        secret = row.secret.name(),
                        secrets_storage = %declared,
                        duplicate_store = %store,
                        "{} is also stored in the {store} store, which this deployment does not \
                         read. It is ignored today and becomes live if SECRETS_STORAGE ever \
                         changes to {store}. Remove it with `bunyip-api secrets-purge --confirm`.",
                        row.secret.name(),
                    );
                }
            }
        }
    }

    fatal
}

/// Render a store list for an operator message ("environment and infisical").
fn store_list(stores: &[SecretsStorage]) -> String {
    let names: Vec<&str> = stores.iter().map(|store| store.as_str()).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Write one governed secret to `storage`, the declared store.
///
/// Used by the admin save path and by `secrets-migrate`, so there is exactly one
/// write-through per store. `environment` has no writable store (a process
/// cannot set a variable for its own next boot, and the compose secret files are
/// mounted read-only), which is reported as a 409 rather than a silent success.
///
/// `updated_by` is the admin making the change on the admin path. `None` is the
/// `secrets-migrate` path: it writes the ciphertext without claiming an operator
/// edited the configuration, and `updated_by` is a FK to `users`, which a CLI
/// run has no row for.
pub async fn write_secret(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    storage: SecretsStorage,
    secret: GovernedSecret,
    value: &str,
    updated_by: Option<uuid::Uuid>,
) -> Result<(), AppError> {
    match storage {
        SecretsStorage::Environment => Err(read_only_store_error(secret)),
        SecretsStorage::Database => {
            let (ciphertext, nonce, key_version) = encrypt_secret(key_set, value)?;
            let (secret_key, webhook_secret) = match secret {
                GovernedSecret::StripeSecretKey => (
                    (Some(ciphertext.clone()), Some(nonce.clone())),
                    (None, None),
                ),
                _ => (
                    (None, None),
                    (Some(ciphertext.clone()), Some(nonce.clone())),
                ),
            };
            match (secret, updated_by) {
                (GovernedSecret::SmtpPassword, Some(admin)) => {
                    EmailConfigRepository::update(
                        pool,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(ciphertext),
                        Some(nonce),
                        key_version,
                        None,
                        None,
                        None,
                        admin,
                    )
                    .await?;
                }
                (GovernedSecret::SmtpPassword, None) => {
                    EmailConfigRepository::update_password_encryption(
                        pool,
                        &ciphertext,
                        &nonce,
                        key_version,
                    )
                    .await?;
                }
                (_, Some(admin)) => {
                    StripeConfigRepository::update(
                        pool,
                        secret_key.0,
                        secret_key.1,
                        webhook_secret.0,
                        webhook_secret.1,
                        admin,
                        key_version,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await?;
                }
                (_, None) => {
                    StripeConfigRepository::update_secret_encryption(
                        pool,
                        secret_key.0,
                        secret_key.1,
                        webhook_secret.0,
                        webhook_secret.1,
                        key_version,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        SecretsStorage::Infisical => {
            let client = InfisicalClient::from_settings(&config.infisical)
                .ok_or_else(infisical_unconfigured_error)?;
            client
                .upsert_secret(secret.name(), value)
                .await
                .map_err(|e| {
                    error!(
                        error = %e,
                        secret = secret.name(),
                        "failed to write the secret to Infisical"
                    );
                    infisical_write_error(secret, &e.to_string())
                })
        }
    }
}

/// Remove one governed secret's copy from a store that is NOT the declared one
/// (`secrets-purge`). Returns the operator-facing note for the `environment`
/// store, which cannot be written and so is reported instead of removed.
pub async fn purge_secret(
    pool: &PgPool,
    config: &Config,
    secret: GovernedSecret,
    storage: SecretsStorage,
) -> Result<Option<String>, AppError> {
    match storage {
        SecretsStorage::Environment => Ok(Some(format!(
            "remove {}_FILE (and the ./secrets/{} file it points at) from the api service",
            secret.name(),
            secret.secret_file()
        ))),
        SecretsStorage::Database => {
            clear_database_secret(pool, secret).await?;
            Ok(None)
        }
        SecretsStorage::Infisical => {
            let client = InfisicalClient::from_settings(&config.infisical)
                .ok_or_else(infisical_unconfigured_error)?;
            client.delete_secret(secret.name()).await.map_err(|e| {
                error!(error = %e, secret = secret.name(), "failed to delete the secret from Infisical");
                AppError::Upstream {
                    message: format!("Could not delete {} from Infisical: {e}", secret.name()),
                }
            })?;
            Ok(None)
        }
    }
}

/// NULL out one governed secret's ciphertext columns, leaving every non-secret
/// column (host, port, checkout URLs, tier ids) untouched.
async fn clear_database_secret(pool: &PgPool, secret: GovernedSecret) -> Result<(), AppError> {
    let statement = match secret {
        GovernedSecret::SmtpPassword => {
            "UPDATE email_config SET smtp_password = NULL, smtp_password_nonce = NULL, \
             updated_at = NOW() WHERE id = 1"
        }
        GovernedSecret::StripeSecretKey => {
            "UPDATE stripe_config SET secret_key = NULL, secret_key_nonce = NULL, \
             updated_at = NOW() WHERE id = 1"
        }
        GovernedSecret::StripeWebhookSecret => {
            "UPDATE stripe_config SET webhook_secret = NULL, webhook_secret_nonce = NULL, \
             updated_at = NOW() WHERE id = 1"
        }
    };
    sqlx::query(statement).execute(pool).await?;
    Ok(())
}

/// The 409 an admin write gets in `environment` mode: there is no writable
/// store, so reporting success would leave the typed value somewhere nothing
/// reads.
pub fn read_only_store_error(secret: GovernedSecret) -> AppError {
    AppError::Conflict {
        message: format!(
            "SECRETS_STORAGE=environment, so {} is owned by the environment and cannot be changed \
             from the admin pages. Edit the secret file {}_FILE points at (./secrets/{}) and \
             restart bunyip-api.",
            secret.name(),
            secret.name(),
            secret.secret_file()
        ),
    }
}

// =============================================================================
// Operator subcommands: secrets-status / secrets-migrate / secrets-purge
//
// The point of these is that the check runs while the CURRENT deployment is
// healthy. Making a failed boot the discovery mechanism turns a mistake into a
// crash loop under `restart: unless-stopped`, discovered only after the old
// configuration stopped serving. The fatal error stays as the backstop.
// =============================================================================

/// The `secrets-status` report. Carries store membership and readiness only:
/// no secret value ever enters it.
#[derive(Debug, serde::Serialize)]
pub struct StatusReport {
    /// The declared store (`SECRETS_STORAGE`).
    pub declared: String,
    pub secrets: Vec<SecretStatus>,
    /// Set when the Infisical store could not be inspected, so its rows read
    /// "unknown" rather than "empty".
    pub infisical_error: Option<String>,
    /// Whether the Infisical store was inspected at all.
    pub infisical_inspected: bool,
}

/// One governed secret's status: where it lives, what is live, and whether each
/// candidate mode could be switched to today.
#[derive(Debug, serde::Serialize)]
pub struct SecretStatus {
    pub secret: String,
    /// Every inspected store holding a value.
    pub stores: Vec<String>,
    /// The store the running deployment actually reads this value from, or
    /// `None` when the declared store holds nothing.
    pub live_source: Option<String>,
    pub readiness: Vec<ModeReadiness>,
}

/// Whether one candidate mode is ready for this secret, and what to do if not.
#[derive(Debug, serde::Serialize)]
pub struct ModeReadiness {
    pub mode: String,
    pub ready: bool,
    pub note: String,
}

/// Build the status report from a survey. Pure, so the readiness rules are
/// testable and so nothing here can mutate a store.
pub fn status_report(survey: &Survey) -> StatusReport {
    let declared = survey.storage;
    let secrets = survey
        .secrets
        .iter()
        .map(|row| SecretStatus {
            secret: row.secret.name().to_string(),
            stores: row
                .holders
                .iter()
                .map(|store| store.as_str().to_string())
                .collect(),
            live_source: row
                .present_in(declared)
                .then(|| declared.as_str().to_string()),
            readiness: SecretsStorage::ALL
                .iter()
                .map(|mode| {
                    let unknown = *mode == SecretsStorage::Infisical && !survey.infisical_inspected;
                    let ready = row.present_in(*mode);
                    ModeReadiness {
                        mode: mode.as_str().to_string(),
                        ready: ready && !unknown,
                        note: if unknown {
                            "not inspected: Infisical was not contacted in this run".to_string()
                        } else if ready {
                            format!("{} holds a value", mode.as_str())
                        } else {
                            format!(
                                "run `bunyip-api secrets-migrate --to {}` before switching",
                                mode.as_str()
                            )
                        },
                    }
                })
                .collect(),
        })
        .collect();

    StatusReport {
        declared: declared.as_str().to_string(),
        secrets,
        infisical_error: survey.infisical_error.clone(),
        infisical_inspected: survey.infisical_inspected,
    }
}

/// Render the status report as the operator-facing table. Mirrors the JSON
/// exactly, and like it never prints a value.
pub fn render_status(report: &StatusReport) -> String {
    let mut out = format!("SECRETS_STORAGE={} (declared)\n", report.declared);
    if let Some(cause) = &report.infisical_error {
        out.push_str(&format!(
            "warning: the Infisical store could not be inspected: {cause}\n"
        ));
    }
    for secret in &report.secrets {
        let stores = if secret.stores.is_empty() {
            "(none)".to_string()
        } else {
            secret.stores.join(", ")
        };
        out.push_str(&format!("\n{}\n", secret.secret));
        out.push_str(&format!("  stored in:   {stores}\n"));
        out.push_str(&format!(
            "  live source: {}\n",
            secret
                .live_source
                .clone()
                .unwrap_or_else(|| "(none: the feature is off)".to_string())
        ));
        for mode in &secret.readiness {
            out.push_str(&format!(
                "  {:<12} {:<9} {}\n",
                format!("{}:", mode.mode),
                if mode.ready { "ready" } else { "NOT ready" },
                mode.note
            ));
        }
    }
    out
}

/// What `secrets-migrate` will do to one secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationAction {
    /// Copy the live value into the target store.
    Copy,
    /// The target store already holds a value; left untouched.
    AlreadyPresent,
    /// The declared store holds nothing to copy.
    NoSource,
}

/// One planned step.
#[derive(Debug, Clone)]
pub struct MigrationStep {
    pub secret: GovernedSecret,
    pub action: MigrationAction,
}

/// Plan the copy from the current live source into `target`. Pure: `--dry-run`
/// prints exactly this and stops.
pub fn plan_migration(survey: &Survey, target: SecretsStorage) -> Vec<MigrationStep> {
    survey
        .secrets
        .iter()
        .map(|row| MigrationStep {
            secret: row.secret,
            action: if row.present_in(target) {
                MigrationAction::AlreadyPresent
            } else if row.value.is_some() {
                MigrationAction::Copy
            } else {
                MigrationAction::NoSource
            },
        })
        .collect()
}

/// Render a plan as operator-facing lines. For `--to environment` the copy step
/// is a set of instructions, because a process cannot write that store.
pub fn render_plan(steps: &[MigrationStep], target: SecretsStorage, dry_run: bool) -> String {
    let verb = if dry_run { "would copy" } else { "copying" };
    let mut out = format!(
        "secrets-migrate --to {}{}\n",
        target,
        if dry_run { " (dry run)" } else { "" }
    );
    for step in steps {
        let name = step.secret.name();
        match step.action {
            MigrationAction::AlreadyPresent => {
                out.push_str(&format!("  {name}: already present in {target}, skipped\n"));
            }
            MigrationAction::NoSource => {
                out.push_str(&format!(
                    "  {name}: the declared store holds no value, nothing to copy\n"
                ));
            }
            MigrationAction::Copy if target == SecretsStorage::Environment => {
                out.push_str(&format!(
                    "  {name}: add `{name}_FILE: /run/secrets/{file}` to the api service and \
                     write the value to ./secrets/{file} (mode 0600), then re-run \
                     `secrets-status` to verify\n",
                    file = step.secret.secret_file()
                ));
            }
            MigrationAction::Copy => {
                out.push_str(&format!("  {name}: {verb} into {target}\n"));
            }
        }
    }
    out
}

/// Copy every governed secret from its current live source into `target`.
///
/// The old copy is deliberately left in place: it is the rollback path, and
/// deleting it at the moment of cutover removes that path exactly when it is
/// most likely to be needed. `secrets-purge` removes it later, explicitly.
pub async fn run_migration(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    survey: &Survey,
    target: SecretsStorage,
    dry_run: bool,
) -> Result<String, AppError> {
    let steps = plan_migration(survey, target);
    let mut out = render_plan(&steps, target, dry_run);
    if dry_run || target == SecretsStorage::Environment {
        return Ok(out);
    }

    let mut copied = 0usize;
    for step in &steps {
        if step.action != MigrationAction::Copy {
            continue;
        }
        let Some(value) = survey.value(step.secret) else {
            continue;
        };
        write_secret(
            pool,
            config,
            key_set,
            target,
            step.secret,
            value,
            // A CLI copy is not an operator edit of the configuration, so the
            // row's `updated_by` attribution is left alone.
            None,
        )
        .await?;
        copied += 1;
    }
    out.push_str(&format!(
        "\n{copied} secret(s) copied into {target}. The source copies are untouched: set \
         SECRETS_STORAGE={target}, restart, soak, then run `secrets-purge --confirm`.\n"
    ));
    Ok(out)
}

/// Remove every governed-secret copy that sits outside the declared store.
///
/// Refuses unless the declared store holds every governed secret, so a purge can
/// never leave a deployment with no copy at all. Never invoked automatically:
/// only this subcommand, with `--confirm`, deletes anything.
pub async fn run_purge(
    pool: &PgPool,
    config: &Config,
    survey: &Survey,
    confirm: bool,
) -> Result<String, AppError> {
    let declared = survey.storage;
    if !confirm {
        return Err(AppError::BadRequest(
            "secrets-purge deletes secret copies and requires --confirm. Run \
             `bunyip-api secrets-status` first."
                .to_string(),
        ));
    }
    if !survey.complete_in(declared) {
        let missing: Vec<&str> = survey
            .secrets
            .iter()
            .filter(|row| !row.present_in(declared))
            .map(|row| row.secret.name())
            .collect();
        return Err(AppError::BadRequest(format!(
            "the declared {declared} store is not complete ({} missing), so purging the other \
             stores would leave no copy at all. Run `bunyip-api secrets-migrate --to {declared}` \
             first.",
            missing.join(", ")
        )));
    }

    let mut out = format!("secrets-purge (declared store: {declared})\n");
    let mut removed = 0usize;
    for row in &survey.secrets {
        for store in row.holders.iter().filter(|store| **store != declared) {
            match purge_secret(pool, config, row.secret, *store).await? {
                Some(manual) => out.push_str(&format!(
                    "  {}: {store} is not writable from here - {manual}\n",
                    row.secret.name()
                )),
                None => {
                    removed += 1;
                    out.push_str(&format!("  {}: removed from {store}\n", row.secret.name()));
                }
            }
        }
    }
    if removed == 0 && out.lines().count() == 1 {
        out.push_str("  nothing to remove: every copy already sits in the declared store\n");
    }
    Ok(out)
}

/// The error a failed Infisical write reports.
///
/// Error visibility: an Infisical write can fail where a local transaction would
/// not, so the cause reaches the log AND the form. Reported against the field the
/// admin typed into, as a 4xx, because bunyip-web deliberately collapses a 5xx
/// body to a generic line (BUNYIP-477) and here the cause is the whole point.
/// Same shape as the Stripe permission mapping (BUNYIP-516).
fn infisical_write_error(secret: GovernedSecret, cause: &str) -> AppError {
    AppError::validation(
        secret.form_field(),
        format!(
            "Could not write {} to Infisical, so nothing was saved: {cause}. The machine identity \
             needs write access to INFISICAL_SECRET_PATH.",
            secret.name()
        ),
    )
}

/// The error for `SECRETS_STORAGE=infisical` with no usable Infisical client.
fn infisical_unconfigured_error() -> AppError {
    AppError::InternalError {
        message: "SECRETS_STORAGE=infisical, but the Infisical client is not configured. Set \
                  INFISICAL_ENABLED=true plus INFISICAL_ADDRESS, INFISICAL_PROJECT_ID, \
                  INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET (docs/secrets-infisical.md)."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SecretsStorage::{Database, Environment, Infisical};

    /// Row 1 of the enforcement table: present in the declared store, nowhere else.
    #[test]
    fn present_only_in_the_declared_store_is_used() {
        assert_eq!(classify(Database, &[Database]), Enforcement::Use);
        assert_eq!(classify(Environment, &[Environment]), Enforcement::Use);
        assert_eq!(classify(Infisical, &[Infisical]), Enforcement::Use);
    }

    /// Row 2: absent everywhere leaves the feature off.
    #[test]
    fn absent_everywhere_turns_the_feature_off() {
        for declared in SecretsStorage::ALL {
            assert_eq!(classify(declared, &[]), Enforcement::FeatureOff);
        }
    }

    /// Row 3: absent from the declared store, present in another, is fatal and
    /// names the store that holds it.
    #[test]
    fn absent_from_the_declared_store_but_present_elsewhere_is_fatal() {
        assert_eq!(
            classify(Infisical, &[Database]),
            Enforcement::Misplaced(vec![Database])
        );
        assert_eq!(
            classify(Environment, &[Database, Infisical]),
            Enforcement::Misplaced(vec![Database, Infisical])
        );
    }

    /// Row 4: present in the declared store AND elsewhere boots, naming each
    /// duplicate so a later mode change cannot silently promote a stale copy.
    #[test]
    fn a_duplicate_outside_the_declared_store_is_named() {
        assert_eq!(
            classify(Database, &[Environment, Database]),
            Enforcement::Duplicated(vec![Environment])
        );
        assert_eq!(
            classify(Database, &[Environment, Database, Infisical]),
            Enforcement::Duplicated(vec![Environment, Infisical])
        );
    }

    fn survey_of(storage: SecretsStorage, holders: Vec<Vec<SecretsStorage>>) -> Survey {
        Survey {
            storage,
            secrets: GovernedSecret::ALL
                .iter()
                .zip(holders)
                .map(|(secret, holders)| SecretSurvey {
                    secret: *secret,
                    value: holders.contains(&storage).then(|| "hunter2".to_string()),
                    // `survey` reports holders in SecretsStorage::ALL order;
                    // canonicalize so a fixture cannot encode a wrong order.
                    holders: SecretsStorage::ALL
                        .into_iter()
                        .filter(|store| holders.contains(store))
                        .collect(),
                })
                .collect(),
            // The fixtures below describe a run that DID inspect every store;
            // the one test about an uninspected Infisical flips this off.
            infisical_inspected: true,
            infisical_error: None,
        }
    }

    #[test]
    fn enforce_reports_one_fatal_per_misplaced_secret() {
        let survey = survey_of(
            Database,
            vec![vec![Environment], vec![Database], vec![Infisical]],
        );
        let fatal = enforce(&survey);
        assert_eq!(fatal.len(), 2, "{fatal:#?}");
        assert!(fatal[0].contains("SMTP_PASSWORD"), "{fatal:#?}");
        assert!(
            fatal[0].contains("secrets-migrate --to database"),
            "{fatal:#?}"
        );
        assert!(fatal[1].contains("STRIPE_WEBHOOK_SECRET"), "{fatal:#?}");
    }

    #[test]
    fn enforce_is_silent_when_every_secret_sits_only_in_the_declared_store() {
        let survey = survey_of(
            Database,
            vec![vec![Database], vec![Database], vec![Database]],
        );
        assert!(enforce(&survey).is_empty());
        assert!(survey.complete_in(Database));
        assert!(!survey.complete_in(Infisical));
    }

    /// An unreachable Infisical is fatal in `infisical` mode: the operator
    /// declared it the store of record, so "cannot read it" is not "it is empty".
    #[test]
    fn an_unreadable_infisical_is_fatal_only_when_it_is_the_declared_store() {
        let mut survey = survey_of(
            Infisical,
            vec![vec![Infisical], vec![Infisical], vec![Infisical]],
        );
        survey.infisical_error = Some("connection refused".to_string());
        let fatal = enforce(&survey);
        assert_eq!(fatal.len(), 1, "{fatal:#?}");
        assert!(fatal[0].contains("connection refused"), "{fatal:#?}");

        survey.storage = Database;
        survey.secrets = survey_of(
            Database,
            vec![vec![Database], vec![Database], vec![Database]],
        )
        .secrets;
        assert!(enforce(&survey).is_empty());
    }

    #[test]
    fn the_environment_store_refuses_admin_writes_with_a_conflict() {
        let err = read_only_store_error(GovernedSecret::StripeSecretKey);
        assert_eq!(err.error_code(), "CONFLICT");
        let message = err.to_string();
        assert!(message.contains("STRIPE_SECRET_KEY_FILE"), "{message}");
        assert!(message.contains("stripe_secret_key"), "{message}");
    }

    /// `secrets-status` reports store membership, the live source and per-mode
    /// readiness, and prints no secret value.
    #[test]
    fn status_reports_stores_live_source_and_per_mode_readiness() {
        let survey = survey_of(
            Database,
            vec![vec![Database, Environment], vec![Database], vec![]],
        );
        let report = status_report(&survey);
        assert_eq!(report.declared, "database");

        let smtp = &report.secrets[0];
        assert_eq!(smtp.stores, vec!["environment", "database"]);
        assert_eq!(smtp.live_source.as_deref(), Some("database"));
        let ready: Vec<bool> = smtp.readiness.iter().map(|m| m.ready).collect();
        assert_eq!(
            ready,
            vec![true, true, false],
            "environment, database, infisical"
        );
        assert!(smtp.readiness[2]
            .note
            .contains("secrets-migrate --to infisical"));

        // Absent everywhere: no live source, and the feature is off.
        let webhook = &report.secrets[2];
        assert!(webhook.stores.is_empty());
        assert_eq!(webhook.live_source, None);

        // The rendered table and the JSON both carry the store names, never the
        // secret values the survey holds.
        let rendered = render_status(&report);
        let json = serde_json::to_string(&report).unwrap();
        for output in [&rendered, &json] {
            assert!(
                !output.contains("hunter2"),
                "a secret value leaked: {output}"
            );
        }
        assert!(rendered.contains("SECRETS_STORAGE=database (declared)"));
    }

    /// An uninspected Infisical store reads as "not inspected", never as ready:
    /// "we did not look" and "it is empty" are different facts.
    #[test]
    fn an_uninspected_infisical_store_is_never_reported_ready() {
        let mut survey = survey_of(
            Database,
            vec![vec![Database], vec![Database], vec![Database]],
        );
        survey.infisical_inspected = false;
        let report = status_report(&survey);
        let infisical = &report.secrets[0].readiness[2];
        assert!(!infisical.ready);
        assert!(infisical.note.contains("not inspected"), "{infisical:?}");
    }

    /// The migration plan copies only what the target lacks, skips what it
    /// already holds, and says so when there is no source to copy from.
    #[test]
    fn a_migration_plan_copies_only_what_the_target_lacks() {
        let survey = survey_of(
            Database,
            vec![vec![Database], vec![Database, Infisical], vec![]],
        );
        let steps = plan_migration(&survey, Infisical);
        assert_eq!(
            steps.iter().map(|s| s.action.clone()).collect::<Vec<_>>(),
            vec![
                MigrationAction::Copy,
                MigrationAction::AlreadyPresent,
                MigrationAction::NoSource,
            ]
        );

        // `--to environment` cannot write, so the plan is the exact set of
        // {NAME}_FILE entries and secret-file paths to create.
        let env_plan = render_plan(&plan_migration(&survey, Environment), Environment, false);
        assert!(env_plan.contains("SMTP_PASSWORD_FILE: /run/secrets/smtp_password"));
        assert!(env_plan.contains("./secrets/smtp_password"));
        assert!(env_plan.contains("STRIPE_SECRET_KEY_FILE: /run/secrets/stripe_secret_key"));
    }

    /// A dry run says "would copy" and, being a plan, writes nothing: the whole
    /// point of the pre-flight is that it is safe on a running deployment.
    #[test]
    fn a_dry_run_plan_reads_as_a_plan() {
        let survey = survey_of(Database, vec![vec![Database], vec![Database], vec![]]);
        let plan = render_plan(&plan_migration(&survey, Infisical), Infisical, true);
        assert!(plan.contains("(dry run)"), "{plan}");
        assert!(plan.contains("would copy"), "{plan}");
    }

    /// A failed Infisical write reaches the form with its underlying cause, as a
    /// 4xx against the field the admin typed into. A 5xx would be collapsed to
    /// "an unexpected error occurred" by bunyip-web (BUNYIP-477), hiding the one
    /// thing the admin needs (usually a missing write scope).
    #[test]
    fn a_failed_infisical_write_reaches_the_form_with_its_cause() {
        let err = infisical_write_error(
            GovernedSecret::StripeSecretKey,
            "Infisical answered 403 for secret STRIPE_SECRET_KEY: forbidden",
        );
        assert_eq!(err.error_code(), "VALIDATION_ERROR");
        let AppError::ValidationError { field, message } = &err else {
            panic!("expected a field-scoped validation error, got {err:?}");
        };
        assert_eq!(field, GovernedSecret::StripeSecretKey.form_field());
        assert!(message.contains("403"), "{message}");
        assert!(message.contains("nothing was saved"), "{message}");
        assert!(message.contains("write access"), "{message}");
    }

    #[test]
    fn store_lists_read_as_prose() {
        assert_eq!(store_list(&[Database]), "database");
        assert_eq!(
            store_list(&[Environment, Infisical]),
            "environment and infisical"
        );
    }
}
