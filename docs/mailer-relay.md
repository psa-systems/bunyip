# Mailer relay (`POST /v1/mailer/send`)

The send-only API other apps in the PSA suite call instead of holding their own SMTP credentials. Bunyip owns one
verified sending domain (DKIM/SPF/DMARC published for the address in the Email settings' *From*), so every calling app
inherits that deliverability. Added in BUNYIP-602.

## Request

```http
POST /v1/mailer/send
Authorization: Basic base64(<client_id>:<client_secret>)
Content-Type: application/json

{
  "to": "member@customer.example",
  "subject": "Your ticket was updated",
  "text": "Ticket 42 moved to In Progress.",
  "html": "<p>Ticket 42 moved to In Progress.</p>"
}
```

`to`, `subject` and `text` are required; `html` is optional and, when present, is sent as the alternative part. Exactly
one recipient per request. A CR or LF in `to` or `subject` is refused (400) rather than stripped, because a relayed
message is sent from Bunyip's own domain and header injection there would forge mail as the platform.

The `From:` identity is ALWAYS this deployment's configured sending identity. A calling app cannot choose it, so no app
can send as another.

## Responses

| Status | When                                                                                          |
|--------|-----------------------------------------------------------------------------------------------|
| 200    | relayed, or skipped as suppressed; `data.status` is `sent` or `suppressed`                     |
| 400    | the message failed validation (missing field, oversized, header injection, unparseable address) |
| 401    | no HTTP Basic credential, an unknown/disabled `client_id`, or a wrong secret                    |
| 403    | an authentic client whose registration does not list the `client_credentials` grant             |
| 429    | the per-app send cap, or the per-IP failed-authentication cap, was exceeded; see `Retry-After`   |
| 502    | this deployment has no SMTP transport configured, so nothing was sent                           |

A 200 with `"status": "suppressed"` means the message was deliberately NOT delivered: the recipient is on the shared
suppression list (see below). Branch on `status`, not on the HTTP code alone, so a caller can mark that contact
undeliverable in its own data instead of retrying.

## Suppression list and the feedback webhook (BUNYIP-603)

Because every app in the suite relays through one shared sending domain, a single misbehaving recipient (a dead address
that hard-bounces, or someone who marks the mail as spam) degrades that domain's reputation for every other app. Bunyip
keeps one shared suppression list, keyed by recipient address, and refuses to relay to an address on it. The list lives
in the `mailer_suppressions` table and is shared across all calling apps on purpose: it protects the one domain, not any
single app's state.

The list is fed by a signed feedback webhook:

```http
POST /v1/mailer/webhooks/feedback
X-Webhook-Signature: <hex HMAC-SHA256 of the raw body, keyed by MAILER_WEBHOOK_SECRET>
Content-Type: application/json

{
  "event": "bounce",
  "recipient": "dead@customer.example",
  "detail": "550 5.1.1 user unknown"
}
```

- `event` is `bounce` (address does not exist / permanently rejected) or `complaint` (recipient marked the mail as
  spam). Any other value is a 400.
- `recipient` is the affected address; it is stored normalized (trimmed, lowercased), so suppression is
  case-insensitive across the whole address.
- `detail` is optional and kept verbatim for an operator inspecting the suppression later.

The signature is verified against `MAILER_WEBHOOK_SECRET` (the same HMAC-SHA256-hex-in-`X-Webhook-Signature` scheme
bunyip uses for its own outbound webhooks) BEFORE the body is parsed. Verification is fail-closed: with no secret
configured the endpoint answers 500 and logs at `error` (an endpoint that cannot verify a signature must never trust a
body), a missing signature is 401, and a signed-but-malformed body is 400. On success the endpoint answers
`{"status": "recorded", "reason": "bounce"}` and logs the suppression at `warn`.

Provider-neutral by design: the endpoint ingests the normalized shape above, not any one vendor's envelope. Adapting a
specific SMTP provider's bounce/complaint payload (SES/SNS, Postmark, ...) onto this shape is a thin shim in front of
this endpoint; the trust boundary is the signed body.

`/v1/mailer/webhooks/feedback` is in `rate_limit_floor::EXEMPT_PATHS` for the same reason `/v1/webhooks/stripe` is: an
external provider posts every bounce from one address, and the HMAC (not the per-IP floor) is what gates it.

## Rate limits

Both are ordinary `rate_limit_configs` actions, so they appear on the admin Rate Limits page and can be overridden per
deployment there or with the `RATE_LIMIT_{ACTION}_*` env seeds.

| Action                  | Default    | Keyed by            | Purpose                                                     |
|-------------------------|------------|---------------------|--------------------------------------------------------------|
| `mailer_send`           | 60 / 60 s  | calling `client_id` | throughput per calling app                                   |
| `mailer_auth_failures`  | 10 / 60 s  | source IP           | brake on failed authentication, ahead of the Argon2 verify   |

`/v1/mailer/send` is in `rate_limit_floor::EXEMPT_PATHS`: the suite's apps share egress, so the default per-IP floor
would let one app's mail volume throttle another's. The two limits above replace it. The failure cap counts failures
only, so a working calling app never meets it.

## Provisioning a calling app's credential

The credential is an ordinary `oauth_clients` registration, so it is created, rotated and revoked in the one place every
other app identity lives. A registration may relay when it is confidential, authenticates with `client_secret_basic`,
and lists `client_credentials` in `allowed_grant_types`.

1. Generate a secret on the machine that will hold it, and keep the plaintext only in the calling app's own secret
   store:

   ```nu
   openssl rand --hex 32
   ```

2. Hash it with Argon2id. `bunyip_oidc::machine_client::hash_client_secret` is the function the verifier is written
   against; any Argon2id PHC string produced with the same parameters (`Argon2::default()`, or PasswordService's
   `m=65536 t=3 p=4`) verifies, because the parameters are read back out of the stored string.

3. Register the client:

   ```sql
   INSERT INTO oauth_clients (
       client_id, client_secret_hash, client_type, name,
       redirect_uris, post_logout_redirect_uris,
       allowed_scopes, allowed_grant_types,
       token_endpoint_auth_method, require_pkce, audience
   ) VALUES (
       gen_random_uuid(), '<argon2id-hash>', 'confidential', 'mokosh-server',
       ARRAY[]::TEXT[], ARRAY[]::TEXT[],
       ARRAY[]::TEXT[], ARRAY['client_credentials'],
       'client_secret_basic', TRUE, 'https://<this-deployment>/v1'
   )
   RETURNING client_id;
   ```

   No plaintext secret is ever committed to this repo, and no seed migration ships one: the row above is created per
   deployment.

4. Revoke access by setting `disabled_at`. The lookup filters on it, so a disabled registration answers 401 exactly like
   an unregistered one.

There is no CLI or admin screen for this yet; it is tracked in BUNYIP-604.

## Before this can send real mail

- SMTP must be configured for this deployment (admin Email page, or the `SMTP_*` env seeds) and enabled. Until it is,
  the endpoint answers 502 and logs at `error` rather than accepting the message and dropping it.
- DKIM, SPF and DMARC must be published for the sending domain in the *From* address. The endpoint works without them;
  the mail just will not be trusted by receivers.
