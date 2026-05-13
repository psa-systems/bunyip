# Bunyip foundation audit

Captures the rewire decisions for each surface inherited from
`migrate/bunyip-frontend-foundation`. Lives at the root of `full-dev`;
subsequent phases consume the table below.

## Routes (`bunyip-web/src/routes.rs`)

| Route                          | Decision                              | Wires up in |
|--------------------------------|---------------------------------------|-------------|
| `/`                            | KEEP - public landing                 | n/a         |
| `/pricing`                     | KEEP shell, stays `PlaceholderPage` * | future series |
| `/feedback`                    | DROP - no server counterpart          | n/a         |
| `/signup`                      | REWIRE -> `/v1/auth/signup`           | 03          |
| `/login`                       | REWIRE -> `/v1/auth/login`            | 03          |
| `/login/totp`                  | DELETE - merged into LoginPage MFA view | 03        |
| `/login/magic-link`            | DELETE - no server counterpart        | 03          |
| `/verify-email`                | DELETE - no server counterpart        | 03          |
| `/forgot-password`             | REWIRE -> `/v1/auth/password-reset`   | 03          |
| `/reset-password`              | REWIRE -> `/by-token/:token/complete` | 03          |
| `/dashboard`                   | REPLACE - becomes the App Launcher    | 06          |
| `/settings/orgs`               | REWIRE -> `/v1/auth/memberships`      | 04          |
| `/settings/orgs/:slug/members` | REWIRE -> tenants surface             | 04 / 05     |
| `/settings/orgs/:slug/billing` | KEEP shell, stays `PlaceholderPage`   | future series |
| `/invitations/accept`          | REWIRE -> `/v1/auth/invites/by-token/:token` | 03 |
| `/admin/feedback`              | DROP - no server counterpart          | n/a         |
| `/:..segments`                 | KEEP - catch-all stub                 | n/a         |
| `/auth/callback` (NEW)         | ADD - OIDC code exchange              | 03          |
| `/settings/profile` (NEW)      | ADD - profile + change password       | 04          |
| `/settings/security` (NEW)     | ADD - TOTP + recovery codes           | 04          |
| `/settings/sessions` (NEW)     | ADD - active sessions + rename        | 04          |
| `/admin/users` (NEW)           | ADD - user management                 | 05          |
| `/admin/users/invite` (NEW)    | ADD - invite create                   | 05          |
| `/admin/users/invites` (NEW)   | ADD - invite list                     | 05          |
| `/admin/audit-logs` (NEW)      | ADD - paginated audit                 | 05          |
| `/signup/:token` (NEW)         | ADD - self-signup complete            | 03          |

\* "Stays `PlaceholderPage`" = the route + page shell remain, the body is
the catch-all "wired in a later series" stub.

## API modules (`bunyip-web/src/api/`)

All currently assume same-origin `/v1/...` via the Dioxus dev proxy.

| Module       | Decision                                                  | Phase |
|--------------|-----------------------------------------------------------|-------|
| `auth.rs`    | REWIRE to absolute issuer URL + bearer; reshape `login` to handle `LoginOutcome::MfaRequired` | 02 / 03 |
| `me.rs`      | REWIRE -> `GET /v1/auth/me` (mokosh-server surface)       | 02 / 04 |
| `orgs.rs`    | REWIRE -> `/v1/auth/memberships` + `/v1/auth/users`       | 04 / 05 |
| `billing.rs` | KEEP signatures, hit `bunyip-api` until the billing series fires | future |
| `feedback.rs`| DROP (no server counterpart)                              | n/a     |
| `types.rs`   | KEEP - envelope types are reusable                        | 02      |
| `mod.rs`     | REWIRE `request` helper to take absolute URLs + bearer auth | 02 |

## Pages

| Page                         | Decision                                                                                  | Phase |
|------------------------------|-------------------------------------------------------------------------------------------|-------|
| `LandingPage`                | KEEP as-is (public marketing copy)                                                        | n/a   |
| `PricingPage`                | KEEP shell, swap copy to a "not yet" placeholder                                          | n/a   |
| `FeedbackPage`               | DROP                                                                                      | n/a   |
| `SignupPage`                 | PORT from mokosh-clients's signup flow                                                    | 03    |
| `LoginPage`                  | PORT from mokosh-clients's `LoginPage` (password + MFA prompt in one component)           | 03    |
| `LoginTotpPage`              | DELETE                                                                                    | 03    |
| `MagicLinkPage`              | DELETE                                                                                    | 03    |
| `VerifyEmailPage`            | DELETE                                                                                    | 03    |
| `ForgotPasswordPage`         | PORT from mokosh-clients                                                                  | 03    |
| `ResetPasswordPage`          | PORT from mokosh-clients                                                                  | 03    |
| `DashboardPage`              | REPLACE - was orgs-grid; becomes App Launcher tiles                                       | 06    |
| `OrgListPage`                | PORT from mokosh-clients memberships viewer                                               | 04    |
| `OrgMembersPage`             | PORT from mokosh-clients UserManagement                                                   | 05    |
| `OrgBillingPage`             | KEEP shell                                                                                | n/a   |
| `AcceptInvitationPage`       | PORT from mokosh-clients `invite_accept.rs`                                               | 03    |
| `AdminFeedbackPage`          | DROP                                                                                      | n/a   |

## stores/auth.rs

Current: mock-flavored `AuthContext` with placeholder user fields.

Decision: REPLACE with the shape mokosh-clients uses today (`hooks/auth.rs`).
Fields: `user: Option<CurrentUser>`, `tokens: Option<Tokens>`, `active_tenant_id: Option<Uuid>`,
`is_loading: bool`, `error: Option<String>`. Hook surface: `use_auth`, `use_auth_provider`,
`use_require_auth`, `use_require_role`, `use_login_form_with_return_to`, `use_logout`.

Phase: 02 lays the AuthContext shape down; 03 brings the login hooks online.

## components/layout.rs

KEEP bunyip's design. The migrate branch's NavBar / AppLayout / PageHeader are reused;
we do not lift mokosh-clients's nav.

Settings nav items after phase 04 / 05:

- Profile (`/settings/profile`)
- Security (`/settings/security`)
- Active sessions (`/settings/sessions`)
- Organisations (`/settings/orgs`)
- Admin > Users (`/admin/users`)               [role-gated]
- Admin > Audit logs (`/admin/audit-logs`)     [role-gated]

## bunyip-api / crates/bunyip-mocks

KEEP for now. Once phase 02 lands and bunyip-web no longer hits bunyip-api in any code path,
delete `bunyip-api/`, `crates/bunyip-mocks/`, and the `seeds/` directory. The
`compose.dev.yml` web-only service can stand alone against the mokosh-server backend.

Decision logged; deletion lands at the end of phase 02 once the SPA has been verified
without the mock backend.
