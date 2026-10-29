# Host secrets (BUNYIP-983)

A suite product sometimes needs a secret bunyip already holds. `GET /v1/host/secrets/{KEY}` serves one, to a registered
calling app, read-only, with a per-registration allow-list.

The first and so far only key is `mokosh/google_oauth_client`: the Google OAuth client the hosted Mokosh deployments use
to sync a customer's contacts. Before this an operator set the pair in bunyip and then pasted it again into Mokosh's own
secret store (PMS-1430), which is two homes for one value and two chances to rotate only one of them.

## The route

```
GET /v1/host/secrets/mokosh/google_oauth_client
Authorization: Basic base64(client_id:client_secret)
```

```json
{ "data": { "key": "mokosh/google_oauth_client", "value": "{\"client_id\":\"...\",\"client_secret\":\"...\"}" } }
```

`value` is a string, and for this key it is JSON carrying both halves. One key rather than two because the reader wants
both or neither: an id with the previous secret authenticates as nothing.

HTTP Basic, not a bearer, because that is the machine credential this deployment issues. `/oauth2/token` implements
`authorization_code` and `refresh_token` only, and the mailer relay (BUNYIP-602) authenticates the same way, so one
`machine-client disable` revokes a calling app everywhere.

### What it answers

| Answer | When |
| --- | --- |
| `200` | the credential is good and the key is in this registration's `allowed_secret_keys` |
| `401` | no Basic header, an unknown or disabled registration, or a wrong secret |
| `403` | authentic, and the key is not in this registration's allow-list |
| `404` | allow-listed, and either not a key this build serves or nothing is set for it |

The entitlement is checked before the key is looked up, so the route cannot be walked to learn which secrets the host
holds. A disabled registration answers `401`, indistinguishable from an unregistered one, which is what revoking access
has to mean.

Caps: `host_secret_read` (30/minute per calling app) and `host_secret_auth_failures` (10/minute per source IP, failures
only). Both are editable on the admin Rate limits page.

## Registering a calling app

```nu
docker compose exec api bunyip-api machine-client register --name mokosh-host-secrets --secret-key mokosh/google_oauth_client
```

The secret is printed once and is not stored; copy it into the calling app's secret store immediately. A key the
deployment does not serve is refused here rather than at read time, with the servable keys listed.

The allow-list is default-deny: a registration made without `--secret-key` can read nothing, and so can every
registration that existed before this feature.

To rotate the credential, or to revoke it:

```nu
docker compose exec api bunyip-api machine-client rotate --client-id <uuid>
docker compose exec api bunyip-api machine-client disable --client-id <uuid>
```

## Setting the Mokosh Google client

Admin > Mokosh. The client id is shown, because it is public: it travels in every sign-in redirect. The secret is
write-only, like every other governed secret on the admin pages, and the page says which provider holds it.

The secret is the governed secret `MOKOSH_GOOGLE_CLIENT_SECRET`, so `SECRETS_STORAGE` decides where it lives:
`mokosh_config.google_client_secret` under `database`, `MOKOSH_GOOGLE_CLIENT_SECRET_FILE` under `environment` (read-only
from the admin page, as every governed secret is in that mode), `<path>/MOKOSH_GOOGLE_CLIENT_SECRET` under `infisical`.
See [configuration.md](configuration.md#the-governed-secrets-and-secrets_storage-bunyip-38542642).

### Changing the client id stops every tenant's sync

A Mokosh tenant's Google permission was granted to a specific client. Change the id and every one of those grants stops
working until each tenant reconnects their Google account. So the admin page refuses a changed id once, says that, and
accepts the same change on a second submit ("Save anyway").

Rotating the secret alone is safe: nobody has to reconnect. That is the reason the two halves are separate fields rather
than one blob in the form.

Every save writes an `audit_logs` row naming the admin, the client id, whether the secret changed, which provider it
went to, and the SHA-256 of a changed secret so two saves can be told apart. Never the secret itself.

## Adding a second key

1. Add a variant to `HostSecret` in `bunyip-api/src/host_secrets.rs` with its key and how to resolve it. A key that is
   not a variant is not servable, whatever an allow-list says, which is what stops a typo in a column from handing out
   `STRIPE_SECRET_KEY`.
2. If it is a new secret rather than a view over settings bunyip already holds, add it to `GovernedSecret` and give it a
   database home, an `ENV_INVENTORY` entry and a row in `configuration.md` (the `check-doc-surface` gate fails until
   those agree).
3. Add the key to the reading app's registration: `machine-client register --secret-key <key>` for a new app, or an
   `UPDATE` on `oauth_clients.allowed_secret_keys` for one that exists.
