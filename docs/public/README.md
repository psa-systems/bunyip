# Bunyip

Bunyip is the identity and secrets platform at the center of the fleet. One deployment serves sign-in, two-factor, device management, OIDC OP tokens for every other application in the fleet, feedback intake, an OCI registry for internal images, and a small host-secrets channel for allow-listed machine clients. If a service in the fleet needs a user to prove who they are, or needs a credential it did not start with, it talks to bunyip.

## Who these docs are for

Two audiences, both external.

- **Deployment operators** standing bunyip up at a site, configuring Infisical, pointing downstream relying parties (RPs) at it, and keeping it running.
- **End users** of a bunyip-authenticated product: signing in, enrolling a second factor, managing devices, submitting feedback.

Each page names its audience in the first paragraph.

## When not to use bunyip

- You want a general-purpose identity provider to resell to arbitrary SaaS. Bunyip is a fleet component: it issues tokens to a known set of RPs, not to the internet. Use a dedicated hosted OP.
- You need IdP federation to pull users from Entra ID, Google Workspace, Okta, etc. Bunyip is the OP, not a broker. Users sign in to bunyip directly today.
- You need a general-purpose secrets manager end users can edit. Bunyip's host-secrets channel is a small, allow-listed read API for machine clients; Infisical (which bunyip can read from) is the general secret store.

## Where to start

- **Running bunyip for the first time.** Read [Getting started](getting-started.md), then [Installation](installation.md) once you decide to host it for real.
- **Standing up the stack.** [Installation](installation.md) plus [Configuration](configuration.md) cover a from-scratch deployment.
- **Wiring a new RP.** [OIDC provider](oidc-provider.md) walks through client registration, discovery, PKCE, refresh and revocation.
- **Running it in production.** [Operations](operations/overview.md).
- **Something broke.** [Troubleshooting](troubleshooting.md).

## Fast reference

- Default api port: `4401`. Default web port: `4400`. The api is also the OIDC issuer: `/.well-known/openid-configuration` and `/oauth2/*` live on the api.
- Group-1 startup secrets are files, never environment variables. See [Secrets](secrets.md).
- Every main push republishes these docs. If a page is wrong, open a PR against this repo.
