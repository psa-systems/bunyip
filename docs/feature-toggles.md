# Feature toggles

A feature toggle lets an unfinished or optional feature ship dark: it is off in production, switched on in staging to
test it, then switched on in production when it is ready, with no deploy and no code freeze (BUNYIP-840). Every major
feature gates on one.

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
  admin can flip one, and every flip is audited as `admin_feature_toggle_updated`.

## How a change spreads

| Process        | When it sees a change                                                                           |
|----------------|-------------------------------------------------------------------------------------------------|
| the api that served the save | immediately: the save refreshes its snapshot                                      |
| every other api process | within 60 seconds: each re-reads the table on a timer                                  |
| every bunyip-web process | within 60 seconds: each re-reads the public probe `GET /v1/auth/setup/status` on a timer |

A read that fails never turns a feature on. bunyip-api keeps its last good snapshot (every feature is off before the
first successful read), and bunyip-web leaves every feature off at startup and keeps its last good values after that.

## Adding a toggle

1. Add a variant to `Feature` and to `Feature::ALL`, with its `key()` (snake_case, never renamed later: a renamed key
   reads as a new, off feature), `label()`, `help()` and `issue()`.
2. Gate the feature on it. In bunyip-api read `FeatureToggleCache::enabled(Feature::YourFeature)`; in bunyip-web read
   `views::layout::feature_enabled("your_key")`. Hide every nav entry and answer 404 on every route while it is off.
3. If the feature owns a side effect that must be undone when it is switched off, give it one read site in its own
   module, the way `bunyip_api::tenant_routing::tenant_routing_enabled` does, and a source-scan test that keeps it the
   only one.

No migration, admin form, probe field or settings-archive change is needed: the admin page, the probe and the archive
all iterate the registry and the table.

## The toggles

| Key                | Feature                                                                                          |
|--------------------|--------------------------------------------------------------------------------------------------|
| `organizations`    | organizations and teams (BUNYIP-493). Its value moved here from `tier_config.orgs_enabled`        |
| `tenant_hostnames` | tenant hostnames (BUNYIP-591). While it is off, the Traefik tenant routing file at `BUNYIP_TRAEFIK_DYNAMIC_CONFIG_PATH` is deleted at startup, after every save and on every refresh, and the file writer (BUNYIP-679) must check `tenant_routing_enabled` before every write |

`pricing_enabled` is the one feature switch still stored as a `tier_config` column; moving it into the registry is
BUNYIP-841.

## Operator notes

- After a deploy, check that each toggle on `/admin/features` still has its expected value.
- A settings archive carries the `feature_toggles` rows (see [`settings-archive.md`](settings-archive.md)).
- `BUNYIP_TRAEFIK_DYNAMIC_CONFIG_PATH` is read once at startup; unset means bunyip-api manages no routing file (see
  [`configuration.md`](configuration.md)).
