# Troubleshooting

Five concrete failures operators hit, with the underlying cause and the fix. If the shape of the failure is not here, open [Operations](operations/overview.md) and work backwards.

## A downstream relying party returns 401 after a working period

**Symptom.** Users sign in to the RP successfully for weeks, then every bearer request starts coming back `401`. Nothing changed on the RP.

**Likely cause.** Bunyip rotated the OIDC signing key, and the RP's JWKS cache is stale.

**Fix.**

- On bunyip, verify the rotation: `GET /oauth2/jwks` shows the new `kid` and (during overlap) the old one too. `.well-known/openid-configuration` is unchanged.
- On the RP, clear or shorten the JWKS cache. A library that honours `Cache-Control` on the JWKS response will refresh on the next request after headers expire. A library that caches forever needs a restart or a manual eviction.
- Confirm the `kid` in a failing access token matches a key in the RP's view of JWKS. A mismatch is the "stale cache" signal.

Long-term fix: every downstream RP must refresh JWKS on a schedule, not only on startup.

## Infisical is unreachable at boot

**Symptom.** API boots (migrations run, `/health` returns ok), but SMTP sends and Stripe calls fail. Admin pages for integrations show "last known value" banners.

**Likely cause.** `SECRETS_STORAGE=infisical`, Infisical is unreachable or the Infisical client credentials are wrong. Group-1 secrets are files and are unaffected; Group-2 secrets cannot be fetched.

**Fix.**

- Confirm Infisical is reachable from the api container: `curl -I $INFISICAL_BASE_URL` from inside the container.
- Confirm `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET_FILE` are current. A rotated client secret on Infisical's side with a stale file on bunyip is the common cause.
- As a short-term measure, flip `SECRETS_STORAGE=database` and paste the integration values into the admin Settings pages. The api picks up the change on restart. Flip back after Infisical is reachable.

Group-1 secrets never need this workaround; they are files.

## Login approval holds every sign-in because SMTP is down

**Symptom.** Every sign-in that would have been held returns a claim reference, but no email arrives. Users cannot complete sign-in.

**Likely cause.** SMTP is unreachable, the credentials are wrong, or the mail provider is misconfigured.

**Fix.**

- Confirm SMTP is reachable: a simpler `openssl s_client -connect $SMTP_HOST:$SMTP_PORT -starttls smtp` from inside the api container fails on the same thing without touching bunyip.
- Check the password: Group-2 secret via the admin Settings page (database mode), or in Infisical (infisical mode), or `.env` (environment mode).
- For a brief window while fixing SMTP, flip `MAIL_PROVIDER=log`. The approval link is written to the api log at `info`; an operator reads it and relays to the user out of band. This is a last resort.
- For a longer window, flip `LOGIN_APPROVAL_ENABLED=false`. Every sign-in stops being gated. Re-enable it once mail is back.

Login approval is a security feature; the fallback above trades that security for availability knowingly.

## Two-factor seed no longer opens after a key change

**Symptom.** A user who had working TOTP reports codes are refused. The `two-factor` page still shows them enrolled.

**Likely cause.** `APP_ENCRYPTION_KEY` changed without a seed re-encrypt pass. Every sealed TOTP seed is tied to the key that sealed it; a different key cannot open it. The sign-in page surfaces this specifically rather than a generic 500.

**Fix.**

- On the login two-factor page, a user with recovery codes enters one; the seed is cleared and the user is routed to setup to re-enrol.
- A user with no recovery codes needs a super-admin reset: on the user edit page, the super-admin confirms with their own password + a current factor; the two-factor row is cleared, the user is routed to setup on next sign-in.
- Investigate the key change. `APP_ENCRYPTION_KEY` should not rotate without a re-encrypt migration; the internal docs cover that migration. A deployment that rotated the key without the migration has sealed data it cannot open.

## Static asset 404 after an image refresh

**Symptom.** After a release, the sign-in page or admin page shows broken images or stylesheet references. The browser's dev tools show `404` on an `/assets/<fingerprint>` URL.

**Likely cause.** The browser is serving a cached HTML page that references the previous image's fingerprinted asset paths; the new image serves different fingerprints and 404s the old ones.

**Fix.**

- Hard-refresh the browser (shift-reload). The next HTML fetch names the new fingerprints.
- If the sign-in page is served through a CDN or a reverse proxy with its own cache, invalidate that cache. The HTML page is short-cached by default; a long-cache misconfig at the proxy is the usual root cause.
- Confirm the images are serving the new assets from inside: `curl -I https://${BUNYIP_HOST}/assets/screen-<some-hash>.css` from the host returns `200`. If `404`, the new image did not ship the expected asset; the deployment pulled a broken image.

The asset fingerprint is a feature: every bundle carries its own cacheable path, so the browser never serves a mismatched pair. The `404` is the mismatch asserting itself.
