# General Task Runner

# Two deployables: bunyip-api (actix backend, musl-static image) and
# bunyip-web (Axum SSR frontend, glibc image with bun + tailwind). The
# backend consumes the dunite git dependency
# (https://dev.a8n.run/psa-systems/dunite); it is anonymously readable, so
# builds need no token, but an optional DUNITE_GIT_TOKEN is honoured.

# List available recipes
default:
    @just --list

# -- Hooks ------------------------------------------------------------------

# Install the git pre-commit hook (run once per fresh clone). Writes a stub at .git/hooks/pre-commit that execs `just pre-commit`. Bypass with `git commit --no-verify`.
[group: 'hooks']
install-hooks:
    #!/usr/bin/env nu
    let hook = ".git/hooks/pre-commit"
    # Remove first so a leftover symlink from an older install does not get
    # written through to its target file. `try` swallows the not-found case.
    try { rm $hook }
    "#!/usr/bin/env sh\nexec just pre-commit\n" | save $hook
    ^chmod +x $hook
    print $"Wrote ($hook) -> just pre-commit"

# Run the same checks as .forgejo/workflows/check.yml inside the dev compose `api` container.
[group: 'hooks']
pre-commit: ensure-env
    #!/usr/bin/env nu
    print "\n[pre-commit] cargo fmt --all --check"
    ^docker compose -f compose.dev.yml run --rm --no-deps api cargo fmt --all --check
    print "\n[pre-commit] cargo clippy --workspace --all-targets -- -D warnings"
    ^docker compose -f compose.dev.yml run --rm --no-deps api cargo clippy --workspace --all-targets -- -D warnings
    print "\n[pre-commit] cargo build --workspace --all-targets --locked"
    ^docker compose -f compose.dev.yml run --rm --no-deps api cargo build --workspace --all-targets --locked
    print "\n[pre-commit] cargo test --workspace --lib"
    ^docker compose -f compose.dev.yml run --rm --no-deps api cargo test --workspace --lib
    print "\n[pre-commit] all checks passed"

# -- Checks ----------------------------------------------------------------------

# Umbrella check: build + clippy + fmt + docker builder stage.
[group: 'checks']
check: check-migrations check-workflows check-workflow-shell check-runners check-security check-stripe-env check-key-env check-no-bash check-scrollbars check-build check-clippy check-fmt check-docker

# Gate migration version numbers: unique + strictly increasing (BUNYIP-79).
[group: 'checks']
check-migrations:
    ./scripts/check-migration-versions.nu

# Gate the secret scope of pull_request-triggered workflows (BUNYIP-425).
[group: 'checks']
check-workflows:
    ./scripts/check-workflow-secrets.nu

# Gate that every workflow step runs under Nushell: each job declares the
# Nushell shell under `defaults.run` and no step opts out (BUNYIP-489).
[group: 'checks']
check-workflow-shell:
    ./scripts/check-workflow-shell.nu --self-test
    ./scripts/check-workflow-shell.nu

# Gate the runner labels: the native cargo job stays on the dev image, every
# label carries its reason, no workflow installs at run time what the image
# provides (C toolchain, BUNYIP-444; browser system libraries, BUNYIP-446).
[group: 'checks']
check-runners:
    ./scripts/check-runner-labels.nu

# Gate the security shapes the BUNYIP-426 audit sweep removed (transport-derived
# cookie Secure, rev-pinned dunite, no signup enumeration oracle, digest-pinned
# base images). Grep-only, so it runs without a toolchain.
[group: 'checks']
check-security:
    ./scripts/check-security-invariants.nu

# Gate that Stripe config stays DB-only: no STRIPE_* env surface outside the
# e2e harness (BUNYIP-482).
[group: 'checks']
check-stripe-env:
    ./scripts/check-no-stripe-env.nu

# Gate the single at-rest key: no retired per-consumer encryption-key env names
# (BUNYIP-483).
[group: 'checks']
check-key-env:
    ./scripts/check-no-legacy-key-env.nu

# Gate that scripts/ stays Nushell: no .sh file and no POSIX-shell shebang
# (BUNYIP-490).
[group: 'checks']
check-no-bash:
    ./scripts/check-no-bash.nu

# Gate always-visible scrollbars: no hiding or `thin` rule in the authored or
# built CSS, and the visible styling still present in both (BUNYIP-509).
[group: 'checks']
check-scrollbars:
    ./scripts/check-scrollbars.nu --self-test
    ./scripts/check-scrollbars.nu

# Build every target in the workspace.
[group: 'checks']
check-build:
    cargo build --workspace --all-targets

# Clippy across the workspace with warnings denied.
[group: 'checks']
check-clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Formatting check.
[group: 'checks']
check-fmt:
    cargo fmt --all --check

# Build the api image's builder stage only - catches Docker-build drift cheaply.
[group: 'checks']
check-docker:
    docker build --file bunyip-api/oci-build/Dockerfile --target builder --output type=cacheonly --provenance=false .

# Run fmt + clippy + workspace lib tests inside the pinned rust-builder image.
# For dev boxes with no local Rust toolchain; named volumes keep repeat runs incremental.
[group: 'checks']
check-container:
    docker run --rm \
        -v {{ justfile_directory() }}:/work \
        -v dunite-check-cargo-registry:/usr/local/cargo/registry \
        -v bunyip-check-target:/work/target \
        -w /work \
        -e SQLX_OFFLINE=true \
        ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie \
        bash -c "cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-targets"

# Type-check the workspace.
[group: 'checks']
typecheck:
    cargo check --workspace

# Lint the workspace (clippy).
[group: 'checks']
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Format the workspace.
[group: 'checks']
fmt:
    cargo fmt --all

# Run unit tests. --all-targets (not --lib) so binary-crate tests run too:
# bunyip-web is bin-only and `--lib` skips its whole suite (BUNYIP-271).
[group: 'checks']
test:
    cargo test --workspace --all-targets

# docker compose reads HOST_UID/HOST_GID for the `user:` mapping + dev-image
# build args on shared dev hosts (where the developer's uid is not 1000). These
# MUST be named HOST_UID/HOST_GID - compose.dev.yml interpolates exactly those,
# and a fallback to 1000 makes the container unable to read the bind-mounted,
# host-owned (0700) repo, crash-looping with "can't cd to /app/bunyip-web".
export HOST_UID := `id -u`
export HOST_GID := `id -g`
# bunyip-oidc holds the workspace's only compile-time sqlx::query! macros;
# resolve them against the committed .sqlx cache so local cargo commands need no
# database.
export SQLX_OFFLINE := "true"

compose := "docker compose -f compose.dev.yml "
compose_sso := "docker compose -f compose.dev.yml -f compose.dev-sso.yml "

# -- Development --------------------------------------------------------------

# Create .env from the example if missing, generating the dev secrets that would
# otherwise be empty (the encryption keys must be 32-byte hex or the api panics
# at startup). Existing .env is left untouched.
[private]
ensure-env:
    #!/usr/bin/env nu
    # compose.dev.yml declares the per-developer private network as
    # `external: true`, so compose will NOT create it. Ensure it exists
    # (idempotent: inspect returns 0 when present, otherwise create).
    let user_name = (^whoami | str trim)
    let net = $"dev-bunyip-private-($user_name)"
    if (do { ^docker network inspect $net } | complete | get exit_code) != 0 {
        ^docker network create $net out> /dev/null
    }
    if (".env" | path exists) { return }
    print "Creating .env with generated dev credentials..."
    open .env.example
    | lines
    | where $it !~ '^#'
    | where ($it | is-not-empty)
    | parse '{name}={value}'
    | transpose --header-row --as-record
    | update APP_ENCRYPTION_KEY (random binary 32 | encode hex --lower)
    | update JWT_SECRET (random binary 32 | encode hex --lower)
    | items {|name, value| $"($name)=($value)" }
    | str join "\n"
    | $"($in)\n"
    | save .env
    print "Wrote .env (generated APP_ENCRYPTION_KEY, JWT_SECRET)."

# Generate the dev OIDC signing keypair (Ed25519, kid dev-2026) into ./secrets/oidc
# if missing. bunyip-api IS the OIDC issuer and loads these at startup
# (OIDC_JWT_PRIVATE_KEY_PATH); without them it fails to boot. ./secrets/oidc is
# mounted into the api container at /run/secrets/oidc (see compose.dev.yml). The
# keypair is gitignored; this just makes a fresh clone bootable without manual
# openssl steps. Pre-BUNYIP-38 layouts kept the keys at ./secrets/ directly; they
# are migrated into the subdir automatically.
[private]
ensure-oidc-keys:
    #!/usr/bin/env nu
    mkdir secrets/oidc
    # Migrate the old flat layout (secrets/dev-2026.pem) into secrets/oidc/.
    ["dev-2026.pem", "dev-2026.pub.pem"] | each {|f|
        if (($"secrets/($f)" | path exists) and not ($"secrets/oidc/($f)" | path exists)) {
            mv $"secrets/($f)" $"secrets/oidc/($f)"
            print $"Migrated secrets/($f) -> secrets/oidc/($f)"
        }
    } | ignore
    if (("secrets/oidc/dev-2026.pem" | path exists) and ("secrets/oidc/dev-2026.pub.pem" | path exists)) { return }
    ^openssl genpkey --algorithm ed25519 --out secrets/oidc/dev-2026.pem
    ^openssl pkey --in secrets/oidc/dev-2026.pem --pubout --out secrets/oidc/dev-2026.pub.pem
    print "Generated secrets/oidc/dev-2026.pem (Ed25519 OIDC signing key, kid dev-2026)."

# Create/migrate the production secret files under ./secrets (BUNYIP-38).
# Idempotent wrapper around scripts/init-secrets.nu; see compose.yml quick start.
[group: 'dev']
init-secrets:
    ./scripts/init-secrets.nu

# Start the full dev stack (postgres + api + web) in the foreground.
[group: 'dev']
dev: ensure-env ensure-oidc-keys
    {{ compose }}up --build

# Start the full dev stack detached.
[group: 'dev']
dev-detach: ensure-env ensure-oidc-keys
    {{ compose }}up --build --detach
    @echo ""
    @echo "  web (frontend): http://localhost:4400"
    @echo "  api (backend):  http://localhost:4401"

# Start the Traefik-routed stack on *.a8n.run (detached, for SSO/remote testing).
[group: 'dev']
dev-sso: ensure-env ensure-oidc-keys
    #!/usr/bin/env nu
    let user_name = (^whoami | str trim)
    # compose.dev.yml declares the per-developer private network as
    # `external: true`, so compose will NOT create it. Ensure it exists
    # (idempotent: inspect returns 0 when present, otherwise create).
    let net = $"dev-bunyip-private-($user_name)"
    if (do { ^docker network inspect $net } | complete | get exit_code) != 0 {
        ^docker network create $net out> /dev/null
    }
    {{ compose_sso }}up --build --detach
    print ""
    print $"  bunyip hub:   https://($user_name)-bunyip.a8n.run"
    print $"  OCI registry: https://($user_name)-bunyip-registry.a8n.run  \(when OCI_REGISTRY_ENABLED=true in .env)"

# Register the per-developer OIDC clients (hub + mokosh SPA) in bunyip-api.
# The committed seed migration registers the static staging hosts; dev hosts
# carry ${USER} in their redirect URIs and cannot live in a migration, so this
# recipe upserts them against the running dev DB. Idempotent (ON CONFLICT DO
# UPDATE keeps the redirect URIs current if your username or hosts change).
# Run after `just dev-sso`; paste the printed HUB client_id into .env as
# BUNYIP_OIDC_CLIENT_ID and the SPA client_id into mokosh-apps/.env.
[group: 'dev']
register-dev-clients:
    #!/usr/bin/env nu
    let user_name = (^whoami | str trim)
    let pg = $"dev-bunyip-postgres-($user_name)"
    let hub_id = "b0000000-0000-4000-8000-0000000000d1"
    let spa_id = "b0000000-0000-4000-8000-0000000000d2"
    let hub_redirect = $"https://($user_name)-bunyip.a8n.run/auth/callback"
    let spa_redirect = $"https://($user_name)-mokosh.a8n.run/auth/callback"
    let hub_origin = $"https://($user_name)-bunyip.a8n.run"
    let spa_origin = $"https://($user_name)-mokosh.a8n.run"
    let hub_aud = $"https://($user_name)-bunyip-api.a8n.run"
    let spa_aud = $"https://($user_name)-mokosh-api.a8n.run"
    if (do { ^docker inspect $pg } | complete | get exit_code) != 0 {
        print $"FAIL: ($pg) is not running. Run `just dev-sso` first."
        exit 1
    }
    let sql = $"
        INSERT INTO oauth_clients \(
            client_id, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            allowed_scopes, allowed_grant_types,
            token_endpoint_auth_method, require_pkce,
            audience, access_token_ttl_seconds
        \) VALUES
        \('($hub_id)', 'public', 'bunyip-web-dev',
          ARRAY['($hub_redirect)'], ARRAY['($hub_origin)'],
          ARRAY['openid','email','offline_access'], ARRAY['authorization_code','refresh_token'],
          'none', TRUE, '($hub_aud)', 600\),
        \('($spa_id)', 'public', 'mokosh-apps-dev',
          ARRAY['($spa_redirect)'], ARRAY['($spa_origin)'],
          ARRAY['openid','email','offline_access'], ARRAY['authorization_code','refresh_token'],
          'none', TRUE, '($spa_aud)', 600\)
        ON CONFLICT \(client_id\) DO UPDATE
            SET redirect_uris = EXCLUDED.redirect_uris,
                post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
                audience = EXCLUDED.audience;"
    ^docker exec $pg psql --username bunyip --dbname bunyip --quiet --command $sql
    print ""
    print $"  hub  \(BUNYIP_OIDC_CLIENT_ID in bunyip/.env\):        ($hub_id)"
    print $"  SPA  \(MOKOSH_OIDC_CLIENT_ID in mokosh-apps/.env\):   ($spa_id)"

# Stop the dev stack.
[group: 'dev']
dev-stop: ensure-env
    {{ compose }}down

# Stop the Traefik-routed stack.
[group: 'dev']
dev-stop-sso: ensure-env
    {{ compose_sso }}down --remove-orphans

# Automated OCI registry verification against the running dev stack (BUNYIP-31).
# Prerequisites: `just dev-detach` already up with the distribution proxy enabled
# in .env (FORGEJO_BASE_URL, FORGEJO_API_TOKEN, OCI_REGISTRY_ENABLED=true) and a
# published image to pull. Runs the docker login/pull matrix from
# docs/oci-registry-verification.md and exits non-zero on the first failure.
[group: 'dev']
verify-oci slug="bunyip-api" owner="psa-systems-private" image="bunyip-api" tag="v0.1.1":
    #!/usr/bin/env nu
    let user_name = (^whoami | str trim)
    let api_container = $"dev-bunyip-api-($user_name)"
    let pg_container = $"dev-bunyip-postgres-($user_name)"

    # Pull connection details out of .env (never printed).
    let env_vars = (
        open .env | lines
        | where $it !~ '^#'
        | where ($it | is-not-empty)
        | parse '{name}={value}'
        | transpose --header-row --as-record
    )
    let port = (try { $env_vars | get BUNYIP_OCI_PORT } catch { "18081" })
    let registry = $"localhost:($port)"
    let admin = (
        try { $env_vars | get SETUP_DEFAULT_ADMIN } catch {
            print "FAIL: SETUP_DEFAULT_ADMIN missing from .env (needed for docker login)"
            exit 1
        }
    )
    let admin_email = ($admin | split row ':' | first)
    let admin_pass = ($admin | split row ':' | skip 1 | str join ':')

    print $"== OCI registry verification against ($registry) =="

    # Stack must be up.
    if (do { ^docker inspect $api_container } | complete | get exit_code) != 0 {
        print $"FAIL: ($api_container) is not running. Run `just dev-detach` first."
        exit 1
    }

    # Seed (or repoint) the application row the registry serves.
    ^docker exec $pg_container psql --username bunyip --dbname bunyip --quiet --command $"
        INSERT INTO applications \(name, slug, display_name, container_name, oci_image_owner, oci_image_name, pinned_image_tag\)
        VALUES \('{{ slug }}', '{{ slug }}', '{{ slug }}', 'unused', '{{ owner }}', '{{ image }}', '{{ tag }}'\)
        ON CONFLICT \(slug\) DO UPDATE
            SET oci_image_owner = '{{ owner }}', oci_image_name = '{{ image }}', pinned_image_tag = '{{ tag }}';"
    print "seeded application row"

    # 1. Unauthenticated probe must 401 with a WWW-Authenticate challenge.
    let probe = (^curl --silent --include $"http://($registry)/v2/" | str join "\n")
    if not ($probe | str contains "401") { print "FAIL: GET /v2/ did not return 401"; exit 1 }
    if not ($probe | str downcase | str contains "www-authenticate") {
        print "FAIL: 401 response is missing the WWW-Authenticate challenge"; exit 1
    }
    print "PASS: /v2/ auth challenge"

    # 2. docker login with the admin member credentials.
    $admin_pass | ^docker login $registry --username $admin_email --password-stdin
    print "PASS: docker login"

    # 3. Entitled pull of the pinned tag.
    ^docker pull $"($registry)/{{ slug }}:{{ tag }}"
    print "PASS: entitled pull (pinned tag)"

    # 4. A non-pinned tag must be refused.
    let wrong = (do { ^docker pull $"($registry)/{{ slug }}:not-the-pinned-tag" } | complete)
    if $wrong.exit_code == 0 { print "FAIL: pull of a non-pinned tag succeeded"; exit 1 }
    print "PASS: pinned-tag enforcement"

    # 5. Second pull exercises the blob cache (rows touched, no re-fetch).
    ^docker rmi $"($registry)/{{ slug }}:{{ tag }}" out> /dev/null
    ^docker pull $"($registry)/{{ slug }}:{{ tag }}" out> /dev/null
    print "PASS: second pull (blob cache)"

    # Cleanup: remove the test image and registry credentials.
    ^docker rmi $"($registry)/{{ slug }}:{{ tag }}" out> /dev/null
    ^docker logout $registry out> /dev/null
    print ""
    print "== All OCI verification checks passed =="

# Tail all logs.
[group: 'dev']
dev-logs: ensure-env
    {{ compose }}logs --follow

# Tail api logs only.
[group: 'dev']
logs-api: ensure-env
    {{ compose }}logs --follow api

# Tail web logs only.
[group: 'dev']
logs-web: ensure-env
    {{ compose }}logs --follow web

# PostgreSQL shell.
[group: 'dev']
db-shell: ensure-env
    {{ compose }}exec postgres psql --username bunyip --dbname bunyip

# -- Local (cargo, no Docker) ---------------------------------------------------

# Run the api backend locally.
[group: 'local']
run:
    cargo run -p bunyip-api

# Run the web frontend locally (from the crate dir so ServeDir("assets") resolves).
[group: 'local']
run-web:
    cd bunyip-web && cargo run -p bunyip-web

# Build the whole workspace.
[group: 'local']
build:
    cargo build --workspace

# -- Database --------------------------------------------------------------------

# Run pending migrations (also applied automatically on api startup).
[group: 'database']
migrate: ensure-env
    {{ compose }}exec api cargo sqlx migrate run --source bunyip-api/migrations

# Revert the last applied migration.
[group: 'database']
migrate-revert: ensure-env
    {{ compose }}exec api cargo sqlx migrate revert --source bunyip-api/migrations

# Seed the BUNYIP-52 E2E test accounts (e2e-user@a8n.run, e2e-admin@a8n.run).
# Idempotent; runs inside the api container against the dev database. Requires
# BUNYIP_E2E_BOOTSTRAP_ALLOW=true and BUNYIP_E2E_TEST_USER_PASSWORD in the
# container env. Pass flags through, e.g. `just e2e-bootstrap --dry-run` or
# `just e2e-bootstrap --cleanup`.
[group: 'database']
e2e-bootstrap *args: ensure-env
    {{ compose }}exec api cargo run --bin bunyip-e2e-bootstrap -- {{ args }}

# Run the Playwright E2E suite on the HOST against a deployed bunyip instance
# (NOT in a container). Requires e2e/.env filled from e2e/.env.example; runs
# against E2E_BASE_URL. Pass flags through, e.g. `just e2e --headed` or
# `just e2e tests/auth`.
[group: 'database']
e2e *args:
    cd e2e && npx playwright test {{ args }}

# -- Images ----------------------------------------------------------------------

# Build both production images.
[group: 'images']
build-docker: build-api-image build-web-image

# Build the production api image (dunite is anonymous; DUNITE_GIT_TOKEN optional).
[group: 'images']
build-api-image tag="latest":
    docker build \
        --file bunyip-api/oci-build/Dockerfile \
        --secret id=dunite_token,env=DUNITE_GIT_TOKEN \
        --build-arg GIT_COMMIT="$(git rev-parse --short HEAD)" \
        --build-arg GIT_TAG="$(git describe --tags --always --dirty)" \
        --tag bunyip-api:{{ tag }} \
        .

# Build the production web image (context = repo root).
[group: 'images']
build-web-image tag="latest":
    docker build \
        --file bunyip-web/oci-build/Dockerfile \
        --tag bunyip-web:{{ tag }} \
        .

# Export the api static binary to ./dist via the Dockerfile's `export` stage.
[group: 'images']
build-docker-export:
    docker buildx build \
        --file bunyip-api/oci-build/Dockerfile \
        --secret id=dunite_token,env=DUNITE_GIT_TOKEN \
        --build-arg GIT_COMMIT="$(git rev-parse --short HEAD)" \
        --build-arg GIT_TAG="$(git describe --tags --always --dirty)" \
        --target export \
        --output type=local,dest=dist \
        .

# -- Cleanup ------------------------------------------------------------------

# Tear down this repo's dev footprint: stop the compose.dev.yml stack (drops the default network and orphans), remove this repo's per-developer named volumes (postgres data, cargo-target, web node_modules, download/oci caches) plus the bunyip-specific check-container target cache, delete local build artifacts (target/, bunyip-web/node_modules/), and remove the generated dev .env (ensure-env recreates it). Scoped to this repo; safe on a shared host (no host-global prune; shared dunite registry cache left intact).
[group: 'cleanup']
dev-clean:
    #!/usr/bin/env nu
    {{ compose }}down --remove-orphans
    let suffix = $env.USER
    let vols = [
        $"dev-bunyip-postgres-($suffix)"
        $"dev-bunyip-cargo-target-($suffix)"
        $"dev-bunyip-web-node-modules-($suffix)"
        $"dev-bunyip-download-cache-($suffix)"
        $"dev-bunyip-oci-cache-($suffix)"
        "bunyip-check-target"
    ]
    let existing = docker volume ls --quiet | lines
    for vol in $vols {
        if $vol in $existing {
            docker volume rm $vol
        }
    }
    let paths = [target bunyip-web/node_modules .env]
    for p in $paths {
        if ($p | path exists) {
            rm --recursive $p
            print $"removed ($p)"
        }
    }
    print "dev-clean: done"

# Everything dev-clean does, plus remove the Docker images this repo builds and prune its buildx cache. Run for a from-scratch rebuild.
[group: 'cleanup']
dev-clean-all: dev-clean
    #!/usr/bin/env nu
    let images = [
        "bunyip-api:latest"
        "bunyip-web:latest"
    ]
    for img in $images {
        let present = (do { ^docker image inspect $img } | complete).exit_code == 0
        if $present {
            docker image rm $img
        }
    }
    docker buildx prune --force
    print "dev-clean-all: done"

# -- Release ------------------------------------------------------------------

# Create a release (major/minor/hotfix): bump [workspace.package].version, sync Cargo.lock via the pinned rust-builder image (dev boxes have no local cargo; git/fj stay on the host), push the branch, and open the release PR via fj. Needs docker.
[group: 'release']
create-release bump:
    #!/usr/bin/env nu
    let bump = "{{ bump }}"
    let repo = "{{ justfile_directory() }}"

    # The lock sync shells out to docker; fail fast if it is missing, before we create the
    # release branch and leave a half-done release behind.
    if (which docker | is-empty) {
        print $"(ansi red)docker not found. create-release runs the cargo lock-sync in the rust-builder image (dev boxes have no local Rust toolchain); install docker or run the cargo update by hand.(ansi reset)"
        exit 1
    }

    # Abort if there are uncommitted changes
    let status = git status --porcelain | str trim
    if ($status | is-not-empty) {
        print $"(ansi red)Working tree is dirty. Please stash or commit your changes first.(ansi reset)"
        exit 1
    }

    # Switch to main if not already there
    let branch = git branch --show-current | str trim
    if $branch != "main" {
        print $"Switching from ($branch) to main..."
        git checkout main
    }

    # Pull latest changes
    git pull --rebase origin main

    # Calculate next version. bunyip is a workspace, so the single source of
    # truth is `[workspace.package].version` (not `package.version`).
    let current = (open Cargo.toml | get workspace.package.version | split row "." | each { into int })
    let next = match $bump {
        "major" => [$"($current.0 + 1)" "0" "0"],
        "minor" => [$"($current.0)" $"($current.1 + 1)" "0"],
        "hotfix" => [$"($current.0)" $"($current.1)" $"($current.2 + 1)"],
        _ => { print $"(ansi red)Usage: just create-release <major|minor|hotfix>(ansi reset)"; exit 1 }
    }
    let bare = ($next | str join ".")
    let tag = $"v($bare)"
    let release_branch = $"release/($tag)"

    # Abort if the target tag already exists. A stale manifest version must never
    # target an already-published release (BUNYIP-59).
    let existing_tag = (do { ^git rev-parse -q --verify $"refs/tags/($tag)" } | complete)
    if $existing_tag.exit_code == 0 {
        print $"(ansi red)Tag ($tag) already exists. Bump past it or delete the stale tag first.(ansi reset)"
        exit 1
    }

    # Create release branch, bump the workspace version, and commit
    git checkout -b $release_branch
    open Cargo.toml | update workspace.package.version $bare | to toml | collect | save --force Cargo.toml
    git add Cargo.toml
    # The workspace crates inherit version.workspace, so the bump changes their Cargo.lock
    # entries; sync the lock in the same commit or CI's --locked build fails (BUNYIP-59).
    # Name the members explicitly rather than `--workspace`, which would also roll every
    # external dependency forward (BUNYIP-426 F6). Run cargo in the pinned rust-builder image
    # (dev boxes have no local toolchain). Mirrors `check-container`'s mounts so the registry
    # + target caches stay warm. Runs ONLINE so cargo can resolve the dunite-core git
    # dependency (anon-readable, no token); an --offline run cannot check it out. The
    # container runs as root, but Cargo.lock lands world-readable in the host-owned repo,
    # so the host-side git add / commit / checkout all work.
    let docker_args = [
        "run" "--rm"
        "-v" $"($repo):/work"
        "-v" "dunite-check-cargo-registry:/usr/local/cargo/registry"
        "-v" "bunyip-check-target:/work/target"
        "-w" "/work"
        "-e" "SQLX_OFFLINE=true"
        "ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie"
        "bash" "-c" "cargo update --package bunyip-api --package bunyip-web --package bunyip-domain --package bunyip-oci --package bunyip-oidc"
    ]
    ^docker ...$docker_args
    if $env.LAST_EXIT_CODE != 0 {
        print $"(ansi red)the cargo update lock-sync step in the rust-builder container failed (exit ($env.LAST_EXIT_CODE)).(ansi reset)"
        exit 1
    }
    git add Cargo.lock
    git commit --signoff --message $"Release ($tag)"

    # Push release branch
    git push --set-upstream origin $release_branch

    # Open the release PR via fj. Body lives in a tempfile so the
    # changelog can grow later without inline escaping pain.
    let body_file = (mktemp --tmpdir --suffix .md)
    [
        $"Automated release PR for ($tag)."
        ""
        $"After merge, `.forgejo/workflows/create-release.yml` tags and publishes ($tag) to the Generic Packages registry."
    ] | str join "\n" | save --force $body_file
    let fj_result = (^fj --host dev.a8n.run pr create $"Release ($tag)" --body-file $body_file | complete)
    rm $body_file
    if $fj_result.exit_code != 0 {
        print $"(ansi red)fj pr create failed(ansi reset)"
        print $fj_result.stderr
        exit 1
    }

    # `fj pr create` prints `created pull request #N: <title>` on success.
    # Parse the number out and build the PR URL from `origin` so the user
    # gets a clickable link instead of just the fj line.
    let pr_num = (
        $fj_result.stdout
        | str trim
        | parse --regex 'created pull request #(?P<num>\d+)'
        | get num.0?
    )
    let remote = (git remote get-url origin | str trim)
    let base_url = if ($remote | str starts-with "ssh://") {
        $remote | str replace "ssh://git@" "https://" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    } else {
        $remote | str replace --regex "git@([^:]+):" "https://$1/" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    }
    print $"(ansi green)Pushed ($release_branch)(ansi reset)"
    if ($pr_num | is-not-empty) {
        print $"PR: ($base_url)/pulls/($pr_num)"
    } else {
        # fj output format drifted; fall back to whatever it said.
        print $"fj output: ($fj_result.stdout | str trim)"
    }
    print $"After merging, the create-release workflow will tag and release ($tag) automatically."

