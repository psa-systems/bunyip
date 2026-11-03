//! BUNYIP-983: the host secrets bunyip serves to a registered calling app.
//!
//! A suite product sometimes needs a secret bunyip already holds. The first is
//! the Google OAuth client a hosted Mokosh uses for contact sync: before this,
//! an operator set the pair in bunyip for its own use and then pasted it again
//! into Mokosh's secret store (PMS-1430), which is two homes for one value and
//! two chances to rotate only one of them.
//!
//! ## Why a registry and not a key string
//!
//! The route takes a key from the caller, and the obvious implementation looks
//! the key up in the secret store. That implementation hands out
//! `STRIPE_SECRET_KEY` to anybody whose allow-list has a typo in it. So a key
//! is only servable if it is a variant here: the allow-list says which of
//! these a caller may read, and this enum says which keys exist at all. Two
//! gates, and the one that decides what is reachable is in the code rather
//! than in a column an admin edits.
//!
//! ## Why the value is JSON
//!
//! The Mokosh client is a PAIR, and the reader wants both halves or neither:
//! an id with the previous secret authenticates as nothing. One key carrying
//! `{"client_id": "...", "client_secret": "..."}` is one read, one rotation
//! and one failure mode, where two keys would let a reader see half a
//! rotation.

use serde::Serialize;
use sqlx::PgPool;

use crate::errors::AppError;
use bunyip_domain::config::{Config, GovernedSecret};
use bunyip_domain::repositories::MokoshConfigRepository;
use bunyip_domain::services::AppKeySet;

/// A secret this route can serve, by the key a caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSecret {
    /// `mokosh/google_oauth_client`: the Google OAuth client pair a hosted
    /// Mokosh uses for contact sync (PMS-1537 reads it).
    MokoshGoogleOauthClient,
}

/// Every servable key, which is also what `machine-client register
/// --secret-key` validates an operator's spelling against.
pub const HOST_SECRET_KEYS: &[&str] = &[HostSecret::MokoshGoogleOauthClient.key()];

impl HostSecret {
    /// The key as a caller spells it. Namespaced by the product that reads it,
    /// so a second RP's keys cannot collide with Mokosh's.
    pub const fn key(self) -> &'static str {
        match self {
            Self::MokoshGoogleOauthClient => "mokosh/google_oauth_client",
        }
    }

    /// The variant for a key, or `None` for a key this build cannot serve.
    pub fn parse(key: &str) -> Option<Self> {
        match key {
            "mokosh/google_oauth_client" => Some(Self::MokoshGoogleOauthClient),
            _ => None,
        }
    }

    /// The value, or `None` when nothing is set for it yet.
    ///
    /// Both halves or neither: a pair with one half missing is not a usable
    /// credential, and answering with it would send the reader to Google with
    /// an id and no secret, which fails there rather than here.
    pub async fn resolve(
        self,
        pool: &PgPool,
        config: &Config,
        key_set: &AppKeySet,
    ) -> Result<Option<String>, AppError> {
        match self {
            Self::MokoshGoogleOauthClient => {
                let row = MokoshConfigRepository::get(pool).await?;
                let client_id = row.google_client_id.trim().to_string();
                let client_secret = crate::secrets::read_secret(
                    pool,
                    config,
                    key_set,
                    GovernedSecret::MokoshGoogleClientSecret,
                )
                .await?;
                let Some(client_secret) = client_secret else {
                    return Ok(None);
                };
                if client_id.is_empty() {
                    return Ok(None);
                }
                let value = serde_json::to_string(&GoogleOauthClient {
                    client_id,
                    client_secret,
                })
                .map_err(|e| {
                    AppError::internal(format!("could not serialise the host secret: {e}"))
                })?;
                Ok(Some(value))
            }
        }
    }
}

/// The served shape of the Mokosh Google client, which is the contract
/// PMS-1537's provider parses.
#[derive(Debug, Serialize)]
struct GoogleOauthClient {
    client_id: String,
    client_secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_registered_key_is_servable() {
        assert_eq!(
            HostSecret::parse("mokosh/google_oauth_client"),
            Some(HostSecret::MokoshGoogleOauthClient)
        );
        // The point of the registry: a key that names a real governed secret
        // is still not servable, because serving it was never a decision
        // anybody made.
        for unservable in [
            "STRIPE_SECRET_KEY",
            "MOKOSH_GOOGLE_CLIENT_SECRET",
            "mokosh/",
            "mokosh/google_oauth_client ",
            "",
        ] {
            assert_eq!(
                HostSecret::parse(unservable),
                None,
                "{unservable} must not be servable"
            );
        }
    }

    /// The listed keys and the variants cannot drift: the list is built from
    /// the variants' own `key()`.
    #[test]
    fn every_listed_key_parses_back_to_a_variant() {
        for key in HOST_SECRET_KEYS {
            let secret = HostSecret::parse(key).expect("a listed key is servable");
            assert_eq!(secret.key(), *key);
        }
    }

    /// The pair is the contract PMS-1537 reads, so the field names are part of
    /// the wire format and not an implementation detail.
    #[test]
    fn the_served_pair_names_both_halves_the_way_the_reader_expects() {
        let value = serde_json::to_value(GoogleOauthClient {
            client_id: "123456789012-abc.apps.googleusercontent.com".to_string(),
            client_secret: "fixture-client-secret".to_string(),
        })
        .expect("serialise");
        assert_eq!(
            value["client_id"],
            "123456789012-abc.apps.googleusercontent.com"
        );
        assert_eq!(value["client_secret"], "fixture-client-secret");
        assert_eq!(
            value.as_object().map(|o| o.len()),
            Some(2),
            "and nothing else: {value}"
        );
    }
}
