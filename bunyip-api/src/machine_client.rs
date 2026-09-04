//! BUNYIP-604: `bunyip-api machine-client`, the supported way to provision the
//! credential a calling app presents to the mailer relay (BUNYIP-602).
//!
//! A machine credential is an ordinary `oauth_clients` registration, so before
//! this command the only way to create one was a hand-written `INSERT` plus an
//! Argon2id hash produced out of band. That path shipped one registration that
//! was never completed (`20260502000048_register_mokosh_oidc_client.sql`), which
//! is what a documented-but-manual procedure costs.
//!
//! The verbs cover the whole life cycle: `register`, `rotate`, `disable` (the
//! revocation path the relay's `disabled_at IS NULL` lookup already honours) and
//! `list`. The hash is produced by [`hash_client_secret`], the function
//! `verify_machine_client` is written against, so provisioning and checking
//! agree on the format by construction.
//!
//! The plaintext secret exists only in this process and only inside the report
//! this module RETURNS: nothing here writes to a log, a file, or the database
//! except the hash. `main.rs` prints the returned report to stdout exactly once.
//! [`Secret`] redacts itself when formatted for debugging, and
//! `this_module_never_logs` fails the build if a logging or printing macro
//! appears here at all.

use std::fmt;

use anyhow::bail;
use bunyip_oidc::machine_client::{hash_client_secret, MACHINE_GRANT};
use bunyip_oidc::services::oidc_provider::generate_opaque_token;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Printed with every parse failure, so a wrong verb or a missing flag names the
/// whole family rather than just the rule it broke.
pub const USAGE: &str = "\
usage: bunyip-api machine-client <verb>

  register --name <name> [--grant <grant>]...  register a calling app; prints its credential once
  rotate --client-id <uuid>                    replace the secret; prints the new one once
  disable --client-id <uuid>                   revoke the credential (the relay then answers 401)
  list                                         list every registration holding a machine credential
";

/// A parsed `machine-client` invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Register { name: String, grants: Vec<String> },
    Rotate { client_id: Uuid },
    Disable { client_id: Uuid },
    List,
}

/// A generated client secret.
///
/// The `Debug` impl redacts, so the value cannot reach a diagnostic through the
/// derive that every other struct here gets for free.
pub struct Secret(String);

impl Secret {
    /// A fresh 32-byte secret, the length `oidc_provider` issues its opaque
    /// tokens at.
    pub fn generate() -> Self {
        Self(generate_opaque_token(32))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

/// The row `register` writes, split from the INSERT so the shape is testable
/// without a database.
///
/// Every field the relay's checks read is fixed here rather than passed in:
/// confidential, `client_secret_basic`, and [`MACHINE_GRANT`] always listed, so
/// a registration this command produces is usable at a machine endpoint by
/// construction. The URI and scope arrays stay empty: a machine credential
/// never runs a browser redirect flow.
#[derive(Debug, PartialEq, Eq)]
pub struct Registration {
    pub client_id: Uuid,
    pub name: String,
    pub client_type: &'static str,
    pub token_endpoint_auth_method: &'static str,
    pub allowed_grant_types: Vec<String>,
    pub audience: String,
}

impl Registration {
    pub fn new(name: &str, extra_grants: &[String], audience: &str) -> Self {
        let mut allowed_grant_types = vec![MACHINE_GRANT.to_string()];
        for grant in extra_grants {
            if !allowed_grant_types.iter().any(|g| g == grant) {
                allowed_grant_types.push(grant.clone());
            }
        }
        Self {
            client_id: Uuid::new_v4(),
            name: name.to_string(),
            client_type: "confidential",
            token_endpoint_auth_method: "client_secret_basic",
            allowed_grant_types,
            audience: audience.to_string(),
        }
    }
}

/// The audience an access token for this deployment would carry, derived from
/// `APP_URL` the same way the migration-registered clients spell it.
fn audience_for(base_url: &str) -> String {
    format!("{}/v1", base_url.trim_end_matches('/'))
}

/// Value of `--flag`, or `None` when the flag is absent or its value is missing.
///
/// A following token that itself starts with `--` counts as missing, so
/// `--name --grant x` is the usage error it looks like rather than a client
/// literally named `--grant`.
fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let idx = args.iter().position(|arg| arg == name)?;
    args.get(idx + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
}

/// Every value of a repeatable `--flag`.
fn flag_values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, arg)| arg.as_str() == name)
        .filter_map(|(idx, _)| {
            args.get(idx + 1)
                .map(String::as_str)
                .filter(|value| !value.starts_with("--"))
        })
        .collect()
}

fn client_id_flag(args: &[String], verb: &str) -> anyhow::Result<Uuid> {
    let Some(raw) = flag_value(args, "--client-id") else {
        bail!("machine-client {verb} needs --client-id <uuid>\n\n{USAGE}");
    };
    match Uuid::parse_str(raw) {
        Ok(id) => Ok(id),
        Err(_) => bail!("machine-client {verb}: {raw:?} is not a UUID client_id\n\n{USAGE}"),
    }
}

/// Parse the arguments after `machine-client`.
///
/// Every failure is an error carrying [`USAGE`]; no input is a no-op.
pub fn parse(args: &[String]) -> anyhow::Result<Command> {
    let Some(verb) = args.first() else {
        bail!("machine-client needs a verb\n\n{USAGE}");
    };
    match verb.as_str() {
        "register" => {
            let Some(name) = flag_value(args, "--name") else {
                bail!("machine-client register needs --name <name>\n\n{USAGE}");
            };
            Ok(Command::Register {
                name: name.to_string(),
                grants: flag_values(args, "--grant")
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            })
        }
        "rotate" => Ok(Command::Rotate {
            client_id: client_id_flag(args, "rotate")?,
        }),
        "disable" => Ok(Command::Disable {
            client_id: client_id_flag(args, "disable")?,
        }),
        "list" => Ok(Command::List),
        other => bail!("unknown machine-client verb {other:?}\n\n{USAGE}"),
    }
}

/// Run one `machine-client` invocation and return the report for stdout.
pub async fn run(pool: &PgPool, base_url: &str, args: &[String]) -> anyhow::Result<String> {
    match parse(args)? {
        Command::Register { name, grants } => register(pool, &name, &grants, base_url).await,
        Command::Rotate { client_id } => rotate(pool, client_id).await,
        Command::Disable { client_id } => disable(pool, client_id).await,
        Command::List => list(pool).await,
    }
}

/// The one place the plaintext is rendered, and it is rendered into the report
/// the caller prints once. Nothing writes it anywhere else.
fn credential_report(action: &str, name: &str, client_id: Uuid, secret: &Secret) -> String {
    format!(
        "{action} machine client {name:?}\n  client_id: {client_id}\n  secret:    {}\n\n\
         The secret is shown once and is not stored; copy it into the calling app's secret store now.\n",
        secret.expose()
    )
}

async fn register(
    pool: &PgPool,
    name: &str,
    grants: &[String],
    base_url: &str,
) -> anyhow::Result<String> {
    let registration = Registration::new(name, grants, &audience_for(base_url));
    let secret = Secret::generate();
    let hash = hash_client_secret(secret.expose()).await?;

    sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_secret_hash, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            allowed_scopes, allowed_grant_types,
            token_endpoint_auth_method, require_pkce, audience
        ) VALUES (
            $1, $2, $3, $4,
            ARRAY[]::TEXT[], ARRAY[]::TEXT[],
            ARRAY[]::TEXT[], $5,
            $6, TRUE, $7
        )
        "#,
    )
    .bind(registration.client_id)
    .bind(&hash)
    .bind(registration.client_type)
    .bind(&registration.name)
    .bind(&registration.allowed_grant_types)
    .bind(registration.token_endpoint_auth_method)
    .bind(&registration.audience)
    .execute(pool)
    .await?;

    Ok(credential_report(
        "registered",
        &registration.name,
        registration.client_id,
        &secret,
    ))
}

/// `(name, token_endpoint_auth_method, disabled)` for an existing registration.
async fn load(pool: &PgPool, client_id: Uuid) -> anyhow::Result<(String, String, bool)> {
    let row = sqlx::query(
        "SELECT name, token_endpoint_auth_method, disabled_at FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        bail!("no registration with client_id {client_id}");
    };
    Ok((
        row.try_get("name")?,
        row.try_get("token_endpoint_auth_method")?,
        row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("disabled_at")?
            .is_some(),
    ))
}

async fn rotate(pool: &PgPool, client_id: Uuid) -> anyhow::Result<String> {
    let (name, auth_method, disabled) = load(pool, client_id).await?;
    if auth_method != "client_secret_basic" {
        bail!(
            "registration {client_id} ({name:?}) authenticates with {auth_method:?}; \
             it holds no machine credential to rotate"
        );
    }
    if disabled {
        // `disable` is the revocation path and it is terminal: a rotated secret
        // on a disabled row would still answer 401, so say so instead of
        // printing a credential that cannot work.
        bail!(
            "registration {client_id} ({name:?}) is disabled; register a new machine client \
             instead of rotating a revoked one"
        );
    }

    let secret = Secret::generate();
    let hash = hash_client_secret(secret.expose()).await?;
    sqlx::query("UPDATE oauth_clients SET client_secret_hash = $1 WHERE client_id = $2")
        .bind(&hash)
        .bind(client_id)
        .execute(pool)
        .await?;

    Ok(credential_report("rotated", &name, client_id, &secret))
}

async fn disable(pool: &PgPool, client_id: Uuid) -> anyhow::Result<String> {
    let (name, _, disabled) = load(pool, client_id).await?;
    if disabled {
        return Ok(format!(
            "registration {client_id} ({name:?}) was already disabled; nothing changed\n"
        ));
    }
    sqlx::query("UPDATE oauth_clients SET disabled_at = NOW() WHERE client_id = $1")
        .bind(client_id)
        .execute(pool)
        .await?;
    Ok(format!(
        "disabled machine client {name:?} ({client_id}); the relay now answers 401 for it\n"
    ))
}

async fn list(pool: &PgPool) -> anyhow::Result<String> {
    let rows = sqlx::query(
        r#"
        SELECT client_id, name, allowed_grant_types, disabled_at
        FROM oauth_clients
        WHERE client_type = 'confidential'
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(
            "no confidential registrations; nothing holds a machine credential\n".to_string(),
        );
    }

    let mut out = format!("{:<38}{:<24}{:<10}grants\n", "client_id", "name", "state");
    for row in rows {
        let client_id: Uuid = row.try_get("client_id")?;
        let name: String = row.try_get("name")?;
        let grants: Vec<String> = row.try_get("allowed_grant_types")?;
        let disabled = row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("disabled_at")?
            .is_some();
        let state = if disabled { "disabled" } else { "active" };
        // `Uuid`'s Display ignores the formatter's width, so pad the string.
        out.push_str(&format!(
            "{:<38}{name:<24}{state:<10}{}\n",
            client_id.to_string(),
            grants.join(",")
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn register_takes_a_name_and_defaults_to_the_machine_grant() {
        assert_eq!(
            parse(&args(&["register", "--name", "mokosh-server"])).unwrap(),
            Command::Register {
                name: "mokosh-server".to_string(),
                grants: Vec::new(),
            }
        );
    }

    #[test]
    fn register_collects_every_repeated_grant() {
        let parsed = parse(&args(&[
            "register",
            "--name",
            "app",
            "--grant",
            "client_credentials",
            "--grant",
            "refresh_token",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            Command::Register {
                name: "app".to_string(),
                grants: vec![
                    "client_credentials".to_string(),
                    "refresh_token".to_string()
                ],
            }
        );
    }

    #[test]
    fn rotate_and_disable_parse_their_client_id() {
        let id = Uuid::new_v4();
        assert_eq!(
            parse(&args(&["rotate", "--client-id", &id.to_string()])).unwrap(),
            Command::Rotate { client_id: id }
        );
        assert_eq!(
            parse(&args(&["disable", "--client-id", &id.to_string()])).unwrap(),
            Command::Disable { client_id: id }
        );
        assert_eq!(parse(&args(&["list"])).unwrap(), Command::List);
    }

    #[test]
    fn every_bad_invocation_is_an_error_carrying_the_usage() {
        // No verb, an unknown verb, a missing flag, a flag whose value is the
        // next flag, and an unparseable UUID: none of these may be a no-op.
        let bad = [
            args(&[]),
            args(&["provision", "--name", "app"]),
            args(&["register"]),
            args(&["register", "--name"]),
            args(&["register", "--name", "--grant"]),
            args(&["rotate"]),
            args(&["rotate", "--client-id", "not-a-uuid"]),
            args(&["disable"]),
        ];
        for invocation in bad {
            let err = parse(&invocation)
                .expect_err(&format!("{invocation:?} must not parse"))
                .to_string();
            assert!(err.contains("machine-client"), "names the family: {err}");
            assert!(
                err.contains("usage: bunyip-api"),
                "carries the usage: {err}"
            );
        }
    }

    #[test]
    fn a_registration_is_confidential_basic_and_lists_the_machine_grant() {
        let reg = Registration::new("mokosh-server", &[], "https://bunyip.test/v1");
        assert_eq!(reg.client_type, "confidential");
        assert_eq!(reg.token_endpoint_auth_method, "client_secret_basic");
        assert_eq!(reg.allowed_grant_types, vec![MACHINE_GRANT.to_string()]);
        assert_eq!(reg.audience, "https://bunyip.test/v1");
        assert_eq!(reg.name, "mokosh-server");
    }

    #[test]
    fn extra_grants_are_appended_and_never_displace_the_machine_grant() {
        let reg = Registration::new(
            "app",
            &["refresh_token".to_string(), MACHINE_GRANT.to_string()],
            "https://bunyip.test/v1",
        );
        assert_eq!(
            reg.allowed_grant_types,
            vec![MACHINE_GRANT.to_string(), "refresh_token".to_string()],
            "the machine grant is listed once, first"
        );
    }

    #[test]
    fn the_audience_is_the_deployment_url_with_one_slash() {
        assert_eq!(
            audience_for("https://bunyip.test"),
            "https://bunyip.test/v1"
        );
        assert_eq!(
            audience_for("https://bunyip.test/"),
            "https://bunyip.test/v1"
        );
    }

    #[test]
    fn a_secret_redacts_itself_in_diagnostics() {
        let secret = Secret::generate();
        assert!(!secret.expose().is_empty());
        assert_eq!(format!("{secret:?}"), "Secret(redacted)");
        assert!(!format!("{secret:?}").contains(secret.expose()));
    }

    #[test]
    fn the_report_shows_the_secret_once() {
        let secret = Secret::generate();
        let id = Uuid::new_v4();
        let report = credential_report("registered", "app", id, &secret);
        assert_eq!(
            report.matches(secret.expose()).count(),
            1,
            "the plaintext appears exactly once: {report}"
        );
        assert!(report.contains(&id.to_string()));
    }

    #[test]
    fn this_module_never_logs() {
        // The plaintext secret lives in this module, so the module emits no
        // diagnostics at all: `main.rs` prints the returned report and nothing
        // else ever sees the value.
        let source = include_str!("machine_client.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .expect("the test module marks the end of the production half")
            .0;
        for macro_name in [
            "info!(",
            "warn!(",
            "error!(",
            "debug!(",
            "trace!(",
            "println!",
            "print!",
            "eprintln!",
            "eprint!",
            "dbg!(",
        ] {
            assert!(
                !production.contains(macro_name),
                "{macro_name} must not appear in machine_client.rs"
            );
        }
    }
}
