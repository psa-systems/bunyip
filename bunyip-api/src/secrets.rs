//! BUNYIP-542: the governed-secret provider layer.
//!
//! An integration secret used to live in whichever of three places happened to
//! be populated, resolved by a precedence chain nobody could see. Now one
//! required variable, `SECRETS_STORAGE`, declares the provider, and only that
//! provider is consulted. This module is where a governed secret is read from a
//! provider, written to a provider, and where the boot enforcement decides what
//! a copy in the wrong provider means.
//!
//! BUNYIP-642: the variable keeps its `SECRETS_STORAGE` spelling, and the three
//! subcommands below keep their `secrets-*` names, while the vocabulary is
//! provider throughout. Renaming either breaks every running deployment and
//! every runbook for no functional gain.
//!
//! Enforcement, per governed secret, at boot:
//!
//! | Situation                                | Behaviour                                |
//! |------------------------------------------|------------------------------------------|
//! | present in the declared provider         | use it                                   |
//! | absent everywhere                        | feature off, one `warn!`                 |
//! | absent from it, present in another       | fatal: `error!` naming `secrets-migrate` |
//! | present in it AND in another             | boot, one `warn!` naming `secrets-purge` |
//!
//! The last row is what keeps a later mode change honest: a stale copy in a
//! provider nobody reads today becomes live the moment someone flips the mode.

use bunyip_domain::config::{Config, GovernedSecret, SecretsProvider};
use bunyip_domain::errors::AppError;
use bunyip_domain::models::stripe::{decrypt_secret, encrypt_secret};
use bunyip_domain::repositories::{EmailConfigRepository, StripeConfigRepository};
use bunyip_domain::services::{AppKeySet, InfisicalClient};
use sqlx::PgPool;
use tracing::{error, warn};

/// Whether a survey inspects the Infisical provider.
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

/// One governed secret as every inspected provider sees it.
#[derive(Debug, Clone)]
pub struct SecretSurvey {
    pub secret: GovernedSecret,
    /// Every inspected provider that holds a value, in [`SecretsProvider::ALL`] order.
    pub holders: Vec<SecretsProvider>,
    /// The value held by the declared provider, when it holds one. Never logged,
    /// never printed: it exists so a save and a migration can copy it.
    pub value: Option<String>,
}

impl SecretSurvey {
    /// Whether the declared provider holds this secret.
    pub fn present_in(&self, provider: SecretsProvider) -> bool {
        self.holders.contains(&provider)
    }
}

/// Every governed secret, across every inspected provider.
#[derive(Debug, Clone)]
pub struct Survey {
    /// The declared provider this survey was taken against.
    pub provider: SecretsProvider,
    pub secrets: Vec<SecretSurvey>,
    /// Whether the Infisical provider was inspected at all.
    pub infisical_inspected: bool,
    /// The Infisical failure, when the probe ran and could not complete. The
    /// provider's contents are then unknown, which is a different fact from
    /// "the provider is empty" and is reported as such.
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

    /// The declared provider's value for one secret.
    pub fn value(&self, secret: GovernedSecret) -> Option<&str> {
        self.get(secret).value.as_deref()
    }

    /// Whether every governed secret is present in `provider`. `secrets-purge`
    /// refuses to run unless this holds for the declared provider, so a purge can
    /// never leave a deployment with no copy at all.
    pub fn complete_in(&self, provider: SecretsProvider) -> bool {
        self.secrets.iter().all(|row| row.present_in(provider))
    }
}

/// What the boot enforcement decides for one governed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The declared provider holds it and no other inspected provider does.
    Use,
    /// No inspected provider holds it: the feature stays off.
    FeatureOff,
    /// The declared provider is empty but another provider holds it. Fatal: using the
    /// other provider's copy would be exactly the silent precedence this removes,
    /// and ignoring it would disable a feature the operator plainly configured.
    Misplaced(Vec<SecretsProvider>),
    /// The declared provider holds it, and so does another. Boots, but the stale
    /// copy becomes live on a later mode change, so it is named.
    Duplicated(Vec<SecretsProvider>),
}

/// The pure enforcement decision: which provider was declared, which providers hold a
/// value. Kept free of IO so every cell of the table above is unit-tested.
pub fn classify(declared: SecretsProvider, holders: &[SecretsProvider]) -> Enforcement {
    let elsewhere: Vec<SecretsProvider> = holders
        .iter()
        .copied()
        .filter(|provider| *provider != declared)
        .collect();
    match (holders.contains(&declared), elsewhere.is_empty()) {
        (true, true) => Enforcement::Use,
        (true, false) => Enforcement::Duplicated(elsewhere),
        (false, true) => Enforcement::FeatureOff,
        (false, false) => Enforcement::Misplaced(elsewhere),
    }
}

/// Empty is absent. A provider that holds an empty string for a governed secret is
/// not holding it, so `Some("")` becomes `None` before it can be counted as a
/// holder or copied as a value (BUNYIP-621): treating a blank as present is what
/// let a migration report success while leaving the secret unusable. Applied to
/// every provider read in [`survey`], so the survey, the boot enforcement and the
/// migration plan all agree on what "present" means.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

/// Read every governed secret from every provider this run is allowed to inspect.
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
            GovernedSecret::SupportImapPassword => {
                bunyip_domain::config::EmailConfig::db_imap_password(&email_row, key_set)
            }
        }
    };

    // One client, one login per secret read. Built only when the probe runs.
    let client = match probe {
        InfisicalProbe::Skip => None,
        InfisicalProbe::Inspect => InfisicalClient::from_settings(&config.infisical),
    };
    let mut infisical_error = match (probe, &client) {
        // Enabled but half-configured: the credentials are missing, so the provider
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
        // Empty is absent in every provider (BUNYIP-621). `read_environment` already
        // drops an empty file; the database and Infisical reads did not, so a
        // present-but-blank value counted as a holder and a migration reported it
        // "already present" while leaving the secret unusable.
        let database = non_empty(db_value(secret));
        let environment = non_empty(secret.read_environment());
        let infisical = match (&client, infisical_error.is_some()) {
            (Some(client), false) => match client.fetch_secret(secret.name()).await {
                Ok(value) => non_empty(value),
                Err(e) => {
                    infisical_error = Some(e.to_string());
                    None
                }
            },
            _ => None,
        };

        let mut holders = Vec::new();
        for (provider, value) in [
            (SecretsProvider::Environment, &environment),
            (SecretsProvider::Database, &database),
            (SecretsProvider::Infisical, &infisical),
        ] {
            if value.is_some() {
                holders.push(provider);
            }
        }
        let value = match config.secrets_provider {
            SecretsProvider::Environment => environment,
            SecretsProvider::Database => database,
            SecretsProvider::Infisical => infisical,
        };
        secrets.push(SecretSurvey {
            secret,
            holders,
            value,
        });
    }

    Ok(Survey {
        provider: config.secrets_provider,
        secrets,
        infisical_inspected: probe == InfisicalProbe::Inspect && infisical_error.is_none(),
        infisical_error,
    })
}

/// Read ONE governed secret from the declared provider.
///
/// The single-secret form of [`survey`], for request paths that need the live
/// value without inspecting every provider. Same rule: only the declared provider is
/// consulted, so an admin page can never show a value the running service does
/// not use.
pub async fn read_secret(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    secret: GovernedSecret,
) -> Result<Option<String>, AppError> {
    match config.secrets_provider {
        SecretsProvider::Environment => Ok(secret.read_environment()),
        SecretsProvider::Database => match secret {
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
            GovernedSecret::SupportImapPassword => {
                let row = EmailConfigRepository::get(pool).await?;
                Ok(bunyip_domain::config::EmailConfig::db_imap_password(
                    &row, key_set,
                ))
            }
        },
        SecretsProvider::Infisical => {
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
/// from the `stripe_config` row, both secrets from the declared provider.
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
/// says so out loud instead of quietly falling through to another provider.
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
                 APP_ENCRYPTION_KEY_PREV entry; treating the database provider as holding no value \
                 for this secret"
            );
            None
        }
    }
}

/// The boot enforcement: apply [`classify`] to every governed secret, logging
/// each verdict. Returns the fatal reports, if any, so `main.rs` owns the exit.
///
/// The Infisical provider of record being unreachable is fatal on its own in
/// `infisical` mode: the operator declared it as the provider of record, and a
/// silent boot with payments and email disabled serves nobody.
pub fn enforce(survey: &Survey) -> Vec<String> {
    let declared = survey.provider;
    let mut fatal = Vec::new();

    if declared == SecretsProvider::Infisical {
        if let Some(cause) = &survey.infisical_error {
            fatal.push(format!(
                "SECRETS_STORAGE=infisical declares Infisical as the provider of record, but it \
                 could not be read: {cause}. Fix the Infisical connection, or declare a provider \
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
                secrets_provider = %declared,
                "{} is not set in the declared {declared} provider, and no other provider \
                 holds it: {}. Set it on the admin page, or with `bunyip-api secrets-migrate`.",
                row.secret.name(),
                row.secret.feature(),
            ),
            Enforcement::Misplaced(elsewhere) => fatal.push(format!(
                "{} is absent from the declared {declared} provider but present in the {} \
                 provider. bunyip will not silently use a provider the deployment did not \
                 declare. Copy it with `bunyip-api secrets-migrate --to {declared}`, or set \
                 SECRETS_STORAGE to the provider that holds it.",
                row.secret.name(),
                provider_list(&elsewhere),
            )),
            Enforcement::Duplicated(elsewhere) => {
                for provider in elsewhere {
                    warn!(
                        secret = row.secret.name(),
                        secrets_provider = %declared,
                        duplicate_provider = %provider,
                        "{} is also held by the {provider} provider, which this deployment \
                         does not read. It is ignored today and becomes live if SECRETS_STORAGE \
                         ever changes to {provider}. Remove it with `bunyip-api secrets-purge \
                         --confirm`.",
                        row.secret.name(),
                    );
                }
            }
        }
    }

    fatal
}

/// Render a provider list for an operator message ("environment and infisical").
fn provider_list(providers: &[SecretsProvider]) -> String {
    let names: Vec<&str> = providers.iter().map(|provider| provider.as_str()).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Write one governed secret to `provider`, the declared provider.
///
/// Used by the admin save path and by `secrets-migrate`, so there is exactly one
/// write-through per provider. `environment` has no writable provider (a process
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
    provider: SecretsProvider,
    secret: GovernedSecret,
    value: &str,
    updated_by: Option<uuid::Uuid>,
) -> Result<(), AppError> {
    match provider {
        SecretsProvider::Environment => Err(read_only_provider_error(secret)),
        SecretsProvider::Database => {
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
                (GovernedSecret::SupportImapPassword, Some(admin)) => {
                    EmailConfigRepository::update_imap_password(
                        pool,
                        &ciphertext,
                        &nonce,
                        key_version,
                        admin,
                    )
                    .await?;
                }
                (GovernedSecret::SupportImapPassword, None) => {
                    EmailConfigRepository::update_imap_password_encryption(
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
        SecretsProvider::Infisical => {
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

/// Remove one governed secret's copy from a provider that is NOT the declared one
/// (`secrets-purge`). Returns the operator-facing note for the `environment`
/// provider, which cannot be written and so is reported instead of removed.
pub async fn purge_secret(
    pool: &PgPool,
    config: &Config,
    secret: GovernedSecret,
    provider: SecretsProvider,
) -> Result<Option<String>, AppError> {
    match provider {
        SecretsProvider::Environment => Ok(Some(format!(
            "remove {}_FILE (and the ./secrets/{} file it points at) from the api service",
            secret.name(),
            secret.secret_file()
        ))),
        SecretsProvider::Database => {
            clear_database_secret(pool, secret).await?;
            Ok(None)
        }
        SecretsProvider::Infisical => {
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
        GovernedSecret::SupportImapPassword => {
            "UPDATE email_config SET imap_password = NULL, imap_password_nonce = NULL, \
             updated_at = NOW() WHERE id = 1"
        }
    };
    sqlx::query(statement).execute(pool).await?;
    Ok(())
}

/// The 409 an admin write gets in `environment` mode: there is no writable
/// provider, so reporting success would leave the typed value somewhere nothing
/// reads.
pub fn read_only_provider_error(secret: GovernedSecret) -> AppError {
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

/// The `secrets-status` report. Carries provider membership and readiness only:
/// no secret value ever enters it.
#[derive(Debug, serde::Serialize)]
pub struct StatusReport {
    /// The declared provider (`SECRETS_STORAGE`).
    pub declared: String,
    pub secrets: Vec<SecretStatus>,
    /// Set when the Infisical provider could not be inspected, so its rows read
    /// "unknown" rather than "empty".
    pub infisical_error: Option<String>,
    /// Whether the Infisical provider was inspected at all.
    pub infisical_inspected: bool,
}

/// One governed secret's status: where it lives, what is live, and whether each
/// candidate mode could be switched to today.
#[derive(Debug, serde::Serialize)]
pub struct SecretStatus {
    pub secret: String,
    /// Every inspected provider holding a value. The JSON key stays `stores`
    /// (BUNYIP-642): the vocabulary moved, the machine output did not.
    #[serde(rename = "stores")]
    pub providers: Vec<String>,
    /// The provider the running deployment actually reads this value from, or
    /// `None` when the declared provider holds nothing.
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
/// testable and so nothing here can mutate a provider.
pub fn status_report(survey: &Survey) -> StatusReport {
    let declared = survey.provider;
    let secrets = survey
        .secrets
        .iter()
        .map(|row| SecretStatus {
            secret: row.secret.name().to_string(),
            providers: row
                .holders
                .iter()
                .map(|provider| provider.as_str().to_string())
                .collect(),
            live_source: row
                .present_in(declared)
                .then(|| declared.as_str().to_string()),
            readiness: SecretsProvider::ALL
                .iter()
                .map(|mode| {
                    let unknown =
                        *mode == SecretsProvider::Infisical && !survey.infisical_inspected;
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
            "warning: the Infisical provider could not be inspected: {cause}\n"
        ));
    }
    for secret in &report.secrets {
        let providers = if secret.providers.is_empty() {
            "(none)".to_string()
        } else {
            secret.providers.join(", ")
        };
        out.push_str(&format!("\n{}\n", secret.secret));
        out.push_str(&format!("  held by:     {providers}\n"));
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
    /// Copy the live value into the target provider.
    Copy,
    /// The target provider already holds a value; left untouched.
    AlreadyPresent,
    /// The declared provider holds nothing to copy.
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
pub fn plan_migration(survey: &Survey, target: SecretsProvider) -> Vec<MigrationStep> {
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
/// is a set of instructions, because a process cannot write that provider.
pub fn render_plan(
    steps: &[MigrationStep],
    target: SecretsProvider,
    dry_run: bool,
    allow_missing: bool,
) -> String {
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
            // No value in any provider. Left silent it resurfaces later as a broken
            // feature (BUNYIP-621), so it fails the run unless --allow-missing.
            MigrationAction::NoSource if allow_missing => {
                out.push_str(&format!(
                    "  {name}: no value in any provider, skipped (--allow-missing)\n"
                ));
            }
            MigrationAction::NoSource => {
                out.push_str(&format!(
                    "  {name}: no value in any provider; the migration fails unless you set it or \
                     pass --allow-missing\n"
                ));
            }
            MigrationAction::Copy if target == SecretsProvider::Environment => {
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

/// The governed secrets a real migration must refuse to proceed past: those with
/// no value in any provider, which cannot be carried across and would leave the
/// target blank (BUNYIP-621). `--allow-missing` turns this into an explicit skip,
/// so a deployment that genuinely does not use a feature can migrate the rest.
fn migration_blockers(steps: &[MigrationStep], allow_missing: bool) -> Vec<&'static str> {
    if allow_missing {
        return Vec::new();
    }
    steps
        .iter()
        .filter(|step| step.action == MigrationAction::NoSource)
        .map(|step| step.secret.name())
        .collect()
}

/// After a migration, the secrets it copied that the target provider does not now
/// hold with a non-empty value. The re-read survey normalises empty to absent, so
/// a name here means the write reported success without persisting a usable value
/// (BUNYIP-621): the run must fail rather than invite a cutover to a blank provider.
fn verification_failures(
    steps: &[MigrationStep],
    after: &Survey,
    target: SecretsProvider,
) -> Vec<&'static str> {
    steps
        .iter()
        .filter(|step| step.action == MigrationAction::Copy)
        .map(|step| step.secret)
        .filter(|secret| !after.get(*secret).present_in(target))
        .map(|secret| secret.name())
        .collect()
}

/// Copy every governed secret from its current live source into `target`.
///
/// The old copy is deliberately left in place: it is the rollback path, and
/// deleting it at the moment of cutover removes that path exactly when it is
/// most likely to be needed. `secrets-purge` removes it later, explicitly.
///
/// A governed secret with no value in any provider fails the run (BUNYIP-621) unless
/// `allow_missing`, so a silent blank can never be reported as a successful
/// migration. After the copy, the target provider is re-read (`probe` inspects
/// Infisical when it is the target) and any secret that did not land there is a
/// hard failure too, so "reported success" and "actually usable" cannot diverge.
pub async fn run_migration(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    survey: &Survey,
    target: SecretsProvider,
    dry_run: bool,
    allow_missing: bool,
    probe: InfisicalProbe,
) -> Result<String, AppError> {
    let steps = plan_migration(survey, target);
    let mut out = render_plan(&steps, target, dry_run, allow_missing);

    let blockers = migration_blockers(&steps, allow_missing);
    if !blockers.is_empty() {
        return Err(AppError::BadRequest(format!(
            "{out}\n{} has no value in any provider, so migrating to {target} would leave it \
             blank. Set it first, or pass --allow-missing to migrate the rest and leave it \
             unset.",
            blockers.join(", ")
        )));
    }

    if dry_run || target == SecretsProvider::Environment {
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

    // Re-read the providers and confirm every copied secret actually landed in the
    // target (`probe` inspects Infisical when it is the target). Path-qualified
    // because the `survey` parameter shadows the module function here.
    let after = self::survey(pool, config, key_set, probe).await?;
    let blank = verification_failures(&steps, &after, target);
    if !blank.is_empty() {
        return Err(AppError::Upstream {
            message: format!(
                "{out}\nmigration wrote {target} but it still holds no usable value for {}. The \
                 provider did not persist the copy; do NOT set SECRETS_STORAGE={target}.",
                blank.join(", ")
            ),
        });
    }

    out.push_str(&format!(
        "\n{copied} secret(s) copied into {target} and verified present there. The source copies \
         are untouched: set SECRETS_STORAGE={target}, restart, soak, then run \
         `secrets-purge --confirm`.\n"
    ));
    Ok(out)
}

/// Remove every governed-secret copy that sits outside the declared provider.
///
/// Refuses unless the declared provider holds every governed secret, so a purge can
/// never leave a deployment with no copy at all. Never invoked automatically:
/// only this subcommand, with `--confirm`, deletes anything.
pub async fn run_purge(
    pool: &PgPool,
    config: &Config,
    survey: &Survey,
    confirm: bool,
) -> Result<String, AppError> {
    let declared = survey.provider;
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
            "the declared {declared} provider is not complete ({} missing), so purging the \
             other providers would leave no copy at all. Run `bunyip-api secrets-migrate --to \
             {declared}` first.",
            missing.join(", ")
        )));
    }

    let mut out = format!("secrets-purge (declared provider: {declared})\n");
    let mut removed = 0usize;
    for row in &survey.secrets {
        for provider in row.holders.iter().filter(|provider| **provider != declared) {
            match purge_secret(pool, config, row.secret, *provider).await? {
                Some(manual) => out.push_str(&format!(
                    "  {}: {provider} is not writable from here - {manual}\n",
                    row.secret.name()
                )),
                None => {
                    removed += 1;
                    out.push_str(&format!(
                        "  {}: removed from {provider}\n",
                        row.secret.name()
                    ));
                }
            }
        }
    }
    if removed == 0 && out.lines().count() == 1 {
        out.push_str("  nothing to remove: every copy already sits in the declared provider\n");
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
    use SecretsProvider::{Database, Environment, Infisical};

    /// Row 1 of the enforcement table: present in the declared provider, nowhere else.
    #[test]
    fn present_only_in_the_declared_provider_is_used() {
        assert_eq!(classify(Database, &[Database]), Enforcement::Use);
        assert_eq!(classify(Environment, &[Environment]), Enforcement::Use);
        assert_eq!(classify(Infisical, &[Infisical]), Enforcement::Use);
    }

    /// Row 2: absent everywhere leaves the feature off.
    #[test]
    fn absent_everywhere_turns_the_feature_off() {
        for declared in SecretsProvider::ALL {
            assert_eq!(classify(declared, &[]), Enforcement::FeatureOff);
        }
    }

    /// Row 3: absent from the declared provider, present in another, is fatal and
    /// names the provider that holds it.
    #[test]
    fn absent_from_the_declared_provider_but_present_elsewhere_is_fatal() {
        assert_eq!(
            classify(Infisical, &[Database]),
            Enforcement::Misplaced(vec![Database])
        );
        assert_eq!(
            classify(Environment, &[Database, Infisical]),
            Enforcement::Misplaced(vec![Database, Infisical])
        );
    }

    /// Row 4: present in the declared provider AND elsewhere boots, naming each
    /// duplicate so a later mode change cannot silently promote a stale copy.
    #[test]
    fn a_duplicate_outside_the_declared_provider_is_named() {
        assert_eq!(
            classify(Database, &[Environment, Database]),
            Enforcement::Duplicated(vec![Environment])
        );
        assert_eq!(
            classify(Database, &[Environment, Database, Infisical]),
            Enforcement::Duplicated(vec![Environment, Infisical])
        );
    }

    fn survey_of(provider: SecretsProvider, holders: Vec<Vec<SecretsProvider>>) -> Survey {
        Survey {
            provider,
            secrets: GovernedSecret::ALL
                .iter()
                .zip(holders)
                .map(|(secret, holders)| SecretSurvey {
                    secret: *secret,
                    value: holders.contains(&provider).then(|| "hunter2".to_string()),
                    // `survey` reports holders in SecretsProvider::ALL order;
                    // canonicalize so a fixture cannot encode a wrong order.
                    holders: SecretsProvider::ALL
                        .into_iter()
                        .filter(|provider| holders.contains(provider))
                        .collect(),
                })
                .collect(),
            // The fixtures below describe a run that DID inspect every provider;
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
    fn enforce_is_silent_when_every_secret_sits_only_in_the_declared_provider() {
        let survey = survey_of(
            Database,
            vec![vec![Database], vec![Database], vec![Database]],
        );
        assert!(enforce(&survey).is_empty());
        assert!(survey.complete_in(Database));
        assert!(!survey.complete_in(Infisical));
    }

    /// An unreachable Infisical is fatal in `infisical` mode: the operator
    /// declared it the provider of record, so "cannot read it" is not "it is empty".
    #[test]
    fn an_unreadable_infisical_is_fatal_only_when_it_is_the_declared_provider() {
        let mut survey = survey_of(
            Infisical,
            vec![vec![Infisical], vec![Infisical], vec![Infisical]],
        );
        survey.infisical_error = Some("connection refused".to_string());
        let fatal = enforce(&survey);
        assert_eq!(fatal.len(), 1, "{fatal:#?}");
        assert!(fatal[0].contains("connection refused"), "{fatal:#?}");

        survey.provider = Database;
        survey.secrets = survey_of(
            Database,
            vec![vec![Database], vec![Database], vec![Database]],
        )
        .secrets;
        assert!(enforce(&survey).is_empty());
    }

    #[test]
    fn the_environment_provider_refuses_admin_writes_with_a_conflict() {
        let err = read_only_provider_error(GovernedSecret::StripeSecretKey);
        assert_eq!(err.error_code(), "CONFLICT");
        let message = err.to_string();
        assert!(message.contains("STRIPE_SECRET_KEY_FILE"), "{message}");
        assert!(message.contains("stripe_secret_key"), "{message}");
    }

    /// `secrets-status` reports provider membership, the live source and per-mode
    /// readiness, and prints no secret value.
    #[test]
    fn status_reports_providers_live_source_and_per_mode_readiness() {
        let survey = survey_of(
            Database,
            vec![vec![Database, Environment], vec![Database], vec![]],
        );
        let report = status_report(&survey);
        assert_eq!(report.declared, "database");

        let smtp = &report.secrets[0];
        assert_eq!(smtp.providers, vec!["environment", "database"]);
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
        assert!(webhook.providers.is_empty());
        assert_eq!(webhook.live_source, None);

        // The rendered table and the JSON both carry the provider names, never the
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

    /// An uninspected Infisical provider reads as "not inspected", never as ready:
    /// "we did not look" and "it is empty" are different facts.
    #[test]
    fn an_uninspected_infisical_provider_is_never_reported_ready() {
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
        let env_plan = render_plan(
            &plan_migration(&survey, Environment),
            Environment,
            false,
            false,
        );
        assert!(env_plan.contains("SMTP_PASSWORD_FILE: /run/secrets/smtp_password"));
        assert!(env_plan.contains("./secrets/smtp_password"));
        assert!(env_plan.contains("STRIPE_SECRET_KEY_FILE: /run/secrets/stripe_secret_key"));
    }

    /// A dry run says "would copy" and, being a plan, writes nothing: the whole
    /// point of the pre-flight is that it is safe on a running deployment.
    #[test]
    fn a_dry_run_plan_reads_as_a_plan() {
        let survey = survey_of(Database, vec![vec![Database], vec![Database], vec![]]);
        let plan = render_plan(&plan_migration(&survey, Infisical), Infisical, true, false);
        assert!(plan.contains("(dry run)"), "{plan}");
        assert!(plan.contains("would copy"), "{plan}");
    }

    /// Empty is absent in every provider (BUNYIP-621): a present-but-blank value is
    /// dropped before it can be counted as a holder or copied as a source.
    #[test]
    fn empty_is_absent_in_every_provider() {
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(None), None);
        assert_eq!(
            non_empty(Some("sk_live_x".to_string())),
            Some("sk_live_x".to_string())
        );
    }

    /// A secret with no value in any provider (a missing source, an empty source and
    /// an empty target all normalise to this) plans as `NoSource` and stops the
    /// run, so a migration can never report success while leaving it blank. The
    /// operator opts past it explicitly with `--allow-missing`.
    #[test]
    fn a_missing_or_empty_source_blocks_the_migration() {
        let survey = survey_of(
            Database,
            vec![vec![], vec![Database], vec![Database], vec![Database]],
        );
        let steps = plan_migration(&survey, Infisical);
        assert_eq!(steps[0].action, MigrationAction::NoSource);

        assert_eq!(migration_blockers(&steps, false), vec!["SMTP_PASSWORD"]);
        assert!(migration_blockers(&steps, true).is_empty());

        // The plan says which it is: a hard failure by default, an explicit skip
        // under --allow-missing.
        let strict = render_plan(&steps, Infisical, true, false);
        assert!(strict.contains("the migration fails"), "{strict}");
        let allowed = render_plan(&steps, Infisical, true, true);
        assert!(allowed.contains("skipped (--allow-missing)"), "{allowed}");
    }

    /// The post-migration verification pass re-reads the target and flags every
    /// copied secret that did not land there with a usable value, so "reported
    /// success" and "actually present" cannot diverge (BUNYIP-621).
    #[test]
    fn verification_flags_a_copy_that_did_not_land() {
        let source = survey_of(
            Database,
            vec![
                vec![Database],
                vec![Database],
                vec![Database],
                vec![Database],
            ],
        );
        let steps = plan_migration(&source, Infisical);
        assert!(steps.iter().all(|s| s.action == MigrationAction::Copy));

        // Only STRIPE_SECRET_KEY landed in Infisical; SMTP is still blank there.
        let after = survey_of(
            Infisical,
            vec![
                vec![Database],
                vec![Database, Infisical],
                vec![Database],
                vec![Database],
            ],
        );
        let blank = verification_failures(&steps, &after, Infisical);
        assert!(blank.contains(&"SMTP_PASSWORD"), "{blank:?}");
        assert!(!blank.contains(&"STRIPE_SECRET_KEY"), "{blank:?}");

        // A clean migration leaves every copied secret present in the target.
        let clean = survey_of(
            Infisical,
            vec![
                vec![Database, Infisical],
                vec![Database, Infisical],
                vec![Database, Infisical],
                vec![Database, Infisical],
            ],
        );
        assert!(verification_failures(&steps, &clean, Infisical).is_empty());
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
    fn provider_lists_read_as_prose() {
        assert_eq!(provider_list(&[Database]), "database");
        assert_eq!(
            provider_list(&[Environment, Infisical]),
            "environment and infisical"
        );
    }
}
