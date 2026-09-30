# Feature toggles

A feature toggle lets an unfinished or optional feature ship dark: it is off in production, switched on in staging to
test it, then switched on in production when it is ready, with no deploy (BUNYIP-840). Every new major feature gates on
one.

## The rules

- **One registry.** Every toggle is a variant of `Feature` in `crates/bunyip-domain/src/feature_toggles.rs`, stored as
  one row of the `feature_toggles` table.
- **Two states.** On or off. There is no third state and no percentage rollout.
- **Off means invisible.** While a feature is off its routes answer 404 and its nav entries are not rendered. An empty
  page, an error page or a redirect to sign-in would each confirm the route exists.
- **Off by default.** A feature with no row is off, so a new toggle ships dark everywhere until an admin turns it on.
- **Database only.** No environment variable, `CONFIG_KEYS` entry or file-provider key can turn a feature on;
  `no_other_provider_can_turn_a_feature_on` fails the build if one appears.
- **Admin-managed.** The admin Feature Toggles page (`/admin/features`) lists every toggle to any admin. Only the super
  admin can flip one (`PUT /v1/admin/feature-toggles/{key}`, 404 on an unknown key), and every flip is audited as
  `admin_feature_toggle_updated` in the same transaction.

## How a change spreads

| Process                      | When it sees a change                                                                     |
|------------------------------|-------------------------------------------------------------------------------------------|
| the api that served the save | immediately: the save refreshes its snapshot                                              |
| every other api process      | within 60 seconds: each re-reads the table on a timer                                     |
| every bunyip-web process     | within 60 seconds: each re-reads the public probe `GET /v1/auth/setup/status` on a timer |

A read that fails never turns a feature on. bunyip-api keeps its last good snapshot (every feature is off before the
first successful read), and bunyip-web leaves every feature off at startup and keeps its last good values after that.

## Adding a toggle

1. Add a variant to `Feature` and to `Feature::ALL`, with its `key()` (snake_case, never renamed later: a renamed key
   reads as a new, off feature), `label()`, `help()` and `issue()`.
2. Gate the feature on it. In bunyip-api read the `FeatureToggleSnapshot` app data
   (`snapshot.read().enabled(Feature::YourFeature)`); in bunyip-web read `views::layout::feature_enabled("your_key")`.
   Hide every nav entry and answer 404 on every route while it is off.

No migration, admin form, probe field or settings-archive change is needed: the admin page, the probe and the archive
all iterate the registry and the table.

## The toggles

| Key                | Feature                                                                                        |
|--------------------|------------------------------------------------------------------------------------------------|
| `tenant_hostnames` | tenant hostnames (BUNYIP-591). Nothing reads it yet; the routing writer that will gate on it is BUNYIP-679 |

Organizations and teams (`tier_config.orgs_enabled`, BUNYIP-493) and `pricing_enabled` are still `tier_config`
columns, not registry entries. BUNYIP-840 deliberately leaves them there so that reverting it restores today's behavior
exactly; moving `pricing_enabled` in is BUNYIP-841.

## Operator notes

- After a deploy, check that each toggle on `/admin/features` still has its expected value.
- A settings archive carries the `feature_toggles` rows (see [`settings-archive.md`](settings-archive.md)).
