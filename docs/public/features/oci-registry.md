# OCI registry

Bunyip hosts the fleet's internal OCI registry at `/v2/*` on the api. It speaks the OCI distribution-spec v2 to a `docker` or `podman` client, authenticated with bunyip-issued bearer tokens. This page covers the operator view: scopes, repositories, and how a push or pull is gated.

## Scopes

Two scopes gate the registry:

- `oci:pull` lets a token read manifests and blobs.
- `oci:push` lets a token upload blobs and write manifests. Push also implies pull in practice (a tag write needs the base layers).

Scopes are set on the token at mint time, on the admin Clients page or on a user's API token page. A token minted without either scope is a 403 for every registry route.

## Repositories

A repository is a name path such as `platform/bunyip-api` or `services/mokosh-web`. Bunyip does not enforce a namespace schema; a repository exists once a tag is pushed to it. The admin Registry page lists every repository in use with its tag count and the last push timestamp.

Pushing a tag that already exists overwrites the manifest. Pulling the same tag from two clients at different times may return different digests. Deployments that need immutability pin to a digest, not a tag.

## Push flow

A standard OCI push:

1. The client authenticates with a bearer token carrying `oci:push`.
2. `POST /v2/{name}/blobs/uploads/` opens an upload session; bunyip answers with a `Location` pointing at the session UUID.
3. The client PATCHes chunks or PUTs the whole blob with the `digest=sha256:...` query parameter.
4. Repeated for every layer and the config blob.
5. `PUT /v2/{name}/manifests/{tag}` writes the manifest.

Bunyip validates the manifest schema before it accepts the write. A broken manifest is refused `400` and no manifest is stored.

## Pull flow

A pull:

1. The client authenticates with a bearer carrying `oci:pull`.
2. `GET /v2/{name}/manifests/{tag}` returns the manifest.
3. For each layer, `GET /v2/{name}/blobs/{digest}` streams the layer bytes.

Bunyip caches manifests and blobs behind the api and serves from storage; see the internal docs for the storage layout.

## Error handling

Every error path writes a structured error through the api's error context, so the operator sees the cause in the log rather than a bare 500. A write that collides with an in-flight upload returns `409` naming the session; a client that retries the same upload after the session TTL gets `404` and must start a new session.

## What the registry does NOT do

- No content trust (signed manifests). Deployments that need signatures pair the registry with cosign or similar.
- No garbage collection on write. A blob with no manifest referencing it stays until the operator runs the sweep.
- No replication. The registry is a single-host component; two deployments run two independent registries.

## Related

- [API](../api.md) names the registry endpoints alongside the rest.
- [Operations](../operations/overview.md) covers the backup story for registry storage.
