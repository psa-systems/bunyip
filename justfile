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

# docker compose needs these for the `user:` mapping + dev-image HOST_UID/HOST_GID
# build args on shared dev hosts.
export UID := `id -u`
export GID := `id -g`
# bunyip-oidc holds the workspace's only compile-time sqlx::query! macros;
# resolve them against the committed .sqlx cache so local cargo commands need no
# database.
export SQLX_OFFLINE := "true"

compose := "docker compose -f compose.dev.yml "
compose_sso := "docker compose -f compose.dev.yml -f compose.dev-sso.yml "

# ── Dev ───────────────────────────────────────────────────────────────────────

# Create .env from the example if it does not exist yet.
[private]
ensure-env:
    @test -f .env || cp .env.example .env

# Start the full dev stack (postgres + api + web) in the foreground.
dev: ensure-env
    {{ compose }}up --build

# Start the full dev stack detached.
dev-detach: ensure-env
    {{ compose }}up --build --detach
    @echo ""
    @echo "  web (frontend): http://localhost:4400"
    @echo "  api (backend):  http://localhost:4401"

# Start the Traefik-routed stack on *.a8n.run (detached, for SSO/remote testing).
dev-sso: ensure-env
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
dev-stop: ensure-env
    {{ compose }}down

# Stop the Traefik-routed stack.
dev-stop-sso: ensure-env
    {{ compose_sso }}down --remove-orphans

# Stop the stack and remove its named volumes (per-user suffixed on shared hosts).
dev-clean: ensure-env
    {{ compose }}down --volumes

# Tail all logs.
dev-logs: ensure-env
    {{ compose }}logs --follow

# Tail api logs only.
logs-api: ensure-env
    {{ compose }}logs --follow api

# Tail web logs only.
logs-web: ensure-env
    {{ compose }}logs --follow web

# PostgreSQL shell.
db-shell: ensure-env
    {{ compose }}exec postgres psql --username bunyip --dbname bunyip

# ── Local (cargo, no Docker) ───────────────────────────────────────────────────

# Run the api backend locally.
run:
    cargo run -p bunyip-api

# Run the web frontend locally.
run-web:
    cargo run -p bunyip-web

# Build the whole workspace.
build:
    cargo build --workspace

# ── Checks ──────────────────────────────────────────────────────────────────────

# Umbrella check: build + clippy + fmt + docker builder stage.
check: check-build check-clippy check-fmt check-docker

# Build every target in the workspace.
check-build:
    cargo build --workspace --all-targets

# Clippy across the workspace with warnings denied.
check-clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Formatting check.
check-fmt:
    cargo fmt --all --check

# Build the api image's builder stage only - catches Docker-build drift cheaply.
check-docker:
    docker build --file bunyip-api/oci-build/Dockerfile --target builder --tag bunyip-api-builder:check .

# Type-check the workspace.
typecheck:
    cargo check --workspace

# Lint the workspace (clippy).
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Format the workspace.
fmt:
    cargo fmt --all

# Run unit tests.
test:
    cargo test --workspace --lib

# ── Database ────────────────────────────────────────────────────────────────────

# Run pending migrations (also applied automatically on api startup).
migrate: ensure-env
    {{ compose }}exec api cargo sqlx migrate run --source bunyip-api/migrations

# Revert the last applied migration.
migrate-revert: ensure-env
    {{ compose }}exec api cargo sqlx migrate revert --source bunyip-api/migrations

# ── Images ──────────────────────────────────────────────────────────────────────

# Build both production images.
build-docker: build-api-image build-web-image

# Build the production api image (dunite is anonymous; DUNITE_GIT_TOKEN optional).
build-api-image tag="latest":
    docker build \
        --file bunyip-api/oci-build/Dockerfile \
        --secret id=dunite_token,env=DUNITE_GIT_TOKEN \
        --build-arg GIT_COMMIT="$(git rev-parse --short HEAD)" \
        --build-arg GIT_TAG="$(git describe --tags --always --dirty)" \
        --tag bunyip-api:{{ tag }} \
        .

# Build the production web image (context = repo root).
build-web-image tag="latest":
    docker build \
        --file bunyip-web/oci-build/Dockerfile \
        --tag bunyip-web:{{ tag }} \
        .

# Export the api static binary to ./dist via the Dockerfile's `export` stage.
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
