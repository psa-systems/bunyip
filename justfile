# Bunyip (PSA Systems) - task runner for the split web + api workspace.
#
# Two deployables: bunyip-api (actix backend, musl-static image) and
# bunyip-web (Axum SSR frontend, glibc image with bun + tailwind). The
# backend consumes the dunite git dependency
# (https://dev.a8n.run/psa-systems/dunite); it is anonymously readable, so
# builds need no token, but an optional DUNITE_GIT_TOKEN is honoured.

# List available recipes
default:
    @just --list

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

# ── Dev ───────────────────────────────────────────────────────────────────────

# Create .env from the example if missing, generating the dev secrets that would
# otherwise be empty (the encryption keys must be 32-byte hex or the api panics
# at startup). Existing .env is left untouched.
[private]
ensure-env:
    #!/usr/bin/env nu
    if (".env" | path exists) { return }
    print "Creating .env with generated dev credentials..."
    open .env.example
    | lines
    | where $it !~ '^#'
    | where ($it | is-not-empty)
    | parse '{name}={value}'
    | transpose --header-row --as-record
    | update TOTP_ENCRYPTION_KEY (random binary 32 | encode hex --lower)
    | update STRIPE_ENCRYPTION_KEY (random binary 32 | encode hex --lower)
    | update JWT_SECRET (random binary 32 | encode hex --lower)
    | items {|name, value| $"($name)=($value)" }
    | str join "\n"
    | $"($in)\n"
    | save .env
    print "Wrote .env (generated TOTP_ENCRYPTION_KEY, STRIPE_ENCRYPTION_KEY, JWT_SECRET)."

# Generate the dev OIDC signing keypair (Ed25519, kid dev-2026) into ./secrets if
# missing. bunyip-api IS the OIDC issuer and loads these at startup
# (OIDC_JWT_PRIVATE_KEY_PATH); without them it fails to boot. ./secrets is mounted
# into the api container at /run/secrets/oidc (see compose.dev.yml). The keypair is
# gitignored; this just makes a fresh clone bootable without manual openssl steps.
[private]
ensure-oidc-keys:
    #!/usr/bin/env nu
    if (("secrets/dev-2026.pem" | path exists) and ("secrets/dev-2026.pub.pem" | path exists)) { return }
    mkdir secrets
    ^openssl genpkey --algorithm ed25519 --out secrets/dev-2026.pem
    ^openssl pkey --in secrets/dev-2026.pem --pubout --out secrets/dev-2026.pub.pem
    print "Generated secrets/dev-2026.pem (Ed25519 OIDC signing key, kid dev-2026)."

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
    print $"  bunyip hub: https://($user_name)-bunyip.a8n.run"

# Stop the dev stack.
[group: 'dev']
dev-stop: ensure-env
    {{ compose }}down

# Stop the Traefik-routed stack.
[group: 'dev']
dev-stop-sso: ensure-env
    {{ compose_sso }}down --remove-orphans

# Stop the stack, remove its named volumes, and delete the generated dev .env.
[group: 'dev']
dev-clean:
    #!/usr/bin/env nu
    # Named volumes are per-user suffixed on shared hosts; ensure-env recreates .env.
    {{ compose }}down --volumes
    [".env"] | where ($it | path exists) | each {|f| rm $f; print $"Removed ($f)" } | ignore

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

# ── Local (cargo, no Docker) ───────────────────────────────────────────────────

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

# ── Checks ──────────────────────────────────────────────────────────────────────

# Umbrella check: build + clippy + fmt + docker builder stage.
[group: 'checks']
check: check-build check-clippy check-fmt check-docker

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
    docker build --file bunyip-api/oci-build/Dockerfile --target builder --tag bunyip-api-builder:check .

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

# Run unit tests.
[group: 'checks']
test:
    cargo test --workspace --lib

# ── Database ────────────────────────────────────────────────────────────────────

# Run pending migrations (also applied automatically on api startup).
[group: 'database']
migrate: ensure-env
    {{ compose }}exec api cargo sqlx migrate run --source bunyip-api/migrations

# Revert the last applied migration.
[group: 'database']
migrate-revert: ensure-env
    {{ compose }}exec api cargo sqlx migrate revert --source bunyip-api/migrations

# ── Images ──────────────────────────────────────────────────────────────────────

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

# ── Release ─────────────────────────────────────────────────────────────────────

# Create a release: bump major (vx.0.0), minor (v0.x.0), or hotfix (v0.0.x), push the branch, and open the PR via fj.
# After the PR merges, the create-release workflow creates the tag and release automatically.
[group: 'release']
create-release bump:
    #!/usr/bin/env nu
    let bump = "{{ bump }}"

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

    # Create release branch, bump the workspace version, and commit
    git checkout -b $release_branch
    open Cargo.toml | update workspace.package.version $bare | to toml | collect | save --force Cargo.toml
    git add Cargo.toml
    git commit --signoff --message $"Release ($tag)"

    # Push release branch
    git push --set-upstream origin $release_branch

    # Open the release PR via fj. Body lives in a tempfile so the changelog
    # can grow later without inline escaping pain.
    let body_file = (mktemp --tmpdir --suffix .md)
    [
        $"Automated release PR for ($tag)."
        ""
        $"After merge, `.forgejo/workflows/create-release.yml` tags and publishes ($tag)."
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
