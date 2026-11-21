# Branding

For a deployment operator who is making bunyip look like their product, and for the downstream relying parties that read the branding at sign-in. Everything on this page lives on the one `branding` row; nothing here is a literal in the code or a field in `.env`.

## The branding row

Bunyip stores product branding as a single row on the `branding` table. The row owns:

- `product_name` is the display name on the sign-in page, in email subjects, and in RP consent copy.
- `support_email` is the mailto target for the "contact support" link on the sign-in and error pages.
- `palette` is a JSON object of color tokens that downstream renderers read; a canonical palette sits in the admin preview.
- `logo_url` and `logo_mark_url` point at the full logo and the square mark.
- `favicon_url`.
- `legal_links` is an ordered list of `{label, href}` entries rendered at the bottom of auth pages.

Any field that is empty on the row is simply not rendered. Empty means omitted; never a literal placeholder like "Brand name".

A deployment ships with the row absent. On first boot the sign-in page reads `APP_NAME` as a fallback for `product_name`; every other field falls back to a safe empty. The admin Branding page is the one place to populate the row.

## Who reads branding

- **The sign-in page**, before any user has authenticated, reads `GET /v1/branding` and renders product name, logo mark, palette, and legal links.
- **Email templates** read `product_name` from the row at send time. Email subjects never use `APP_NAME` once the row is populated.
- **Downstream relying parties** fetch `GET /v1/branding` when they want the fleet-wide product name and palette. The App Launcher fetches it at load.

## Updating branding

The admin Branding page edits the row and shows a live preview. Save applies without a restart; the sign-in page picks up the new values on its next render (no cache beyond what the browser enforces).

Static assets referenced by `logo_url` and the other image fields must be reachable from a browser that is signed out, because the sign-in page renders before auth. A link to a path behind `/v1/admin/*` will 401 and the asset will be missing.

## Palette

The palette JSON is a flat map of token names to color values. Downstream renderers (bunyip-web, downstream RP UIs) read token names rather than colors, so changing a color never requires an RP deploy.

Tokens the fleet reads today:

- `background`, `surface`, `surface-raised` for the three canvas layers.
- `foreground`, `foreground-muted` for primary and secondary text.
- `accent`, `accent-contrast` for the primary call-to-action.
- `success`, `warning`, `danger` plus their `-contrast` pairs for the three states.
- `border`, `border-muted` for separators.
- `ring` for keyboard focus.

A deployment can add new token names; a downstream RP that does not know a token ignores it. Removing a token (or leaving it empty) makes the RP fall back to its built-in default.

Contrast stays the operator's responsibility: every foreground/background pair must meet AA on the surface it renders on. The amber state (`warning`) is the one where this is routinely missed; the admin preview flags the pair that fails contrast.

## Assets

- The logo full file should be SVG for the sign-in page. A PNG at 2x resolution is acceptable as a fallback.
- The logo mark (favicon and small-chrome uses) should be a square SVG. PNG at 256 and 512 as fallbacks.
- Keep assets under 200 KB each; bunyip does not transcode on the fly.

Assets can be hosted anywhere that is reachable by a signed-out browser. A simple fleet pattern is to put them on the bunyip host under `/static/branding/*` and reference them with absolute URLs; another is to host them on an object store with a CDN. Either works.

## What NEVER goes in branding

- Email sender address (`SMTP_FROM`): that is an environment variable because mail sending starts before the database is reached.
- Legal terms or privacy prose: `legal_links` carries the link, not the content. The content lives wherever the link points.
- Feature toggles: features are not branding even when they look visual. See the Feature flags note in [Configuration](configuration.md).

## Related

- [Configuration](configuration.md) for the `APP_NAME` fallback.
- [Integrations](integrations.md) for how downstream RPs pick up the branding payload.
