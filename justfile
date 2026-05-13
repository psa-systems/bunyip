# Bunyip - Task Runner
#
# Shape mirrors mokosh-clients's justfile; the recipes are adapted for
# bunyip's workspace (bunyip-api native + bunyip-web wasm32 + the mock
# bunyip-mocks crate) and `bunyip-web/package.json` for tailwind.

# Image used by the pre-commit hook. Matches `oci-build/Dockerfile` so
# `just pre-commit` and the Forgejo `check.yml` job run a toolchain
# compatible with the rust-builder-glibc image bunyip is built against.
dev_image := "ghcr.io/niceguyit/rust-builder-glibc:v1.0.0-rust1.94-trixie"

compose_file := "compose.dev.yml"

# List available recipes
default:
    @just --list

# Create .env from .env.example if missing.
[private]
ensure-env:
    @test -f .env || cp .env.example .env

# Install the git pre-commit hook (run once per fresh clone). Writes a
# stub at .git/hooks/pre-commit that execs `just pre-commit`. Bypass
# with `git commit --no-verify`.
install-hooks:
    #!/usr/bin/env nu
    let hook = ".git/hooks/pre-commit"
    # Remove first so a leftover symlink from an older install does not
    # get written through to its target file. `try` swallows the
    # not-found case.
    try { rm $hook }
    "#!/usr/bin/env sh\nexec just pre-commit\n" | save $hook
    ^chmod +x $hook
    print $"Wrote ($hook) -> just pre-commit"

# Run the same checks the Forgejo `check.yml` job runs, inside the
# rust-builder-glibc image so the toolchain matches CI. Native (api +
# mocks) AND wasm (bunyip-web) targets covered.
pre-commit:
    #!/usr/bin/env nu
    let img = "{{ dev_image }}"
    print "\n[pre-commit] cargo fmt --all --check"
    ^docker run --rm --volume $"($env.PWD):/build" --workdir /build --volume dev-bunyip-cargo-target:/build/target --volume dev-bunyip-cargo-registry:/usr/local/cargo/registry $img cargo fmt --all --check
    print "\n[pre-commit] cargo clippy --workspace --all-targets -- -D warnings"
    ^docker run --rm --volume $"($env.PWD):/build" --workdir /build --volume dev-bunyip-cargo-target:/build/target --volume dev-bunyip-cargo-registry:/usr/local/cargo/registry $img cargo clippy --workspace --all-targets -- -D warnings
    print "\n[pre-commit] cargo check (native, excluding bunyip-web)"
    ^docker run --rm --volume $"($env.PWD):/build" --workdir /build --volume dev-bunyip-cargo-target:/build/target --volume dev-bunyip-cargo-registry:/usr/local/cargo/registry $img cargo check --workspace --exclude bunyip-web --all-targets
    print "\n[pre-commit] cargo check --package bunyip-web --target wasm32-unknown-unknown"
    ^docker run --rm --volume $"($env.PWD):/build" --workdir /build --volume dev-bunyip-cargo-target:/build/target --volume dev-bunyip-cargo-registry:/usr/local/cargo/registry $img cargo check --package bunyip-web --target wasm32-unknown-unknown
    print "\n[pre-commit] cargo test --workspace --exclude bunyip-web"
    ^docker run --rm --volume $"($env.PWD):/build" --workdir /build --volume dev-bunyip-cargo-target:/build/target --volume dev-bunyip-cargo-registry:/usr/local/cargo/registry $img cargo test --workspace --exclude bunyip-web
    print "\n[pre-commit] all checks passed"

# Install JS dependencies for the Tailwind build.
[private]
ensure-npm:
    @test -d bunyip-web/node_modules || (cd bunyip-web && bun install)

# Build Tailwind CSS once
css-build: ensure-npm
    cd bunyip-web && bun x @tailwindcss/cli --input input.css --output assets/styles.css

# Watch and rebuild Tailwind CSS on changes
css-watch: ensure-npm
    cd bunyip-web && bun x @tailwindcss/cli --input input.css --output assets/styles.css --watch

# Bring up the dev stack (bunyip-api + bunyip-web), bound to the host
# LAN IP. Trailing args go to `docker compose up` (e.g. --detach,
# --build).
[doc("Start the dev stack in Docker. Trailing args go to `docker compose up` (e.g. --detach, --build).")]
dev *args: ensure-env
    #!/usr/bin/env nu
    let host_ip = (sys net | where name =~ 'eth0|br0' | get ip | flatten | where protocol == 'ipv4' and loop == false | get 0.address)
    let uid = (^id --user | str trim)
    let gid = (^id --group | str trim)
    let user_name = (^whoami | str trim)
    # The base compose.yml declares the per-developer private network
    # as `external: true`, so compose will NOT create it. Ensure it
    # exists (idempotent: inspect returns 0 when present, otherwise
    # create). Same pre-create step exists in `dev-sso` further down.
    let net = $"dev-bunyip-private-($user_name)"
    if (do { ^docker network inspect $net } | complete | get exit_code) != 0 {
        ^docker network create $net out> /dev/null
    }
    print $"Binding bunyip dev stack to ($host_ip) as ($user_name) \(uid ($uid):($gid)\)"
    with-env { BUNYIP_HOST_BIND_IP: $host_ip, HOST_UID: $uid, HOST_GID: $gid, USER: $user_name } {
        docker compose --file {{ compose_file }} up {{ args }}
    }

# Per-developer Traefik-routed instance for SSO testing.
#   Hub: https://{USER}-bunyip.a8n.run
# Run `just dev-sso` here AND in mokosh-server. The overlay requires
# BUNYIP_OIDC_CLIENT_ID set in .env (or the shell), which comes from
# `just register-bunyip-client` in mokosh-server. The compose file
# fails loud if it's missing.
[doc("Start the SSO dev stack (Traefik-routed at https://{USER}-bunyip.a8n.run)")]
dev-sso:
    #!/usr/bin/env nu
    let uid = (^id --user | str trim)
    let gid = (^id --group | str trim)
    let user_name = (^whoami | str trim)
    # The base compose.yml declares the per-developer private network
    # `dev-bunyip-private-${USER}` as `external: true`, so compose
    # will NOT create it. Ensure it exists (idempotent: docker network
    # inspect returns 0 when present, otherwise create).
    let net = $"dev-bunyip-private-($user_name)"
    if (do { ^docker network inspect $net } | complete | get exit_code) != 0 {
        ^docker network create $net out> /dev/null
    }
    # BUNYIP_HOST_BIND_IP is referenced by the base compose.yml's port
    # mapping; the overlay !resets it but the variable still has to
    # substitute, so we set a harmless placeholder. --detach so the
    # URL print runs.
    with-env { BUNYIP_HOST_BIND_IP: "127.0.0.1", HOST_UID: $uid, HOST_GID: $gid, USER: $user_name } {
        docker compose --file {{ compose_file }} --file compose.dev-sso.yml up --build --detach
    }
    print ""
    print $"Bunyip hub: https://($user_name)-bunyip.a8n.run"

# Stop everything this repo runs (both LAN-IP and SSO modes), regardless
# of which `just dev*` you started with. Volumes preserved.
# `--remove-orphans` cleans up containers from either compose-file
# layout. BUNYIP_HOST_BIND_IP is set defensively so the base compose's
# port substitution does not warn during teardown.
[doc("Stop the dev stack (LAN-IP and SSO modes). Volumes preserved.")]
down:
    #!/usr/bin/env nu
    let user_name = (^whoami | str trim)
    let net = $"dev-bunyip-private-($user_name)"
    if (do { ^docker network inspect $net } | complete | get exit_code) != 0 {
        ^docker network create $net out> /dev/null
    }
    with-env { BUNYIP_HOST_BIND_IP: "127.0.0.1", USER: $user_name } {
        docker compose --file {{ compose_file }} --file compose.dev-sso.yml down --remove-orphans
    }

# Bring the SSO dev stack down and back up. Useful after pulling a
# code change or editing compose env vars: `down` waits for containers
# to fully terminate before `dev-sso` starts the fresh ones, so the
# rebuild picks up the new state. `down` is synchronous (docker
# compose down blocks until removal completes) and `dev-sso` uses
# `--detach`, so this returns once the new stack is up.
[doc("Stop the dev stack and start dev-sso fresh.")]
restart: down dev-sso

# Stop the LAN-IP dev stack. Volumes preserved.
[doc("Stop the LAN-IP dev stack (volumes preserved)")]
dev-down: ensure-env
    docker compose --file {{ compose_file }} down

# Stop the SSO dev stack. Volumes preserved.
[doc("Stop the SSO dev stack (volumes preserved)")]
dev-sso-down:
    docker compose --file {{ compose_file }} --file compose.dev-sso.yml down

# Wipe the dev stack: stop, remove volumes (cargo cache included). Use
# sparingly.
[doc("Wipe dev volumes (cargo cache + named volumes).")]
dev-clean: ensure-env
    docker compose --file {{ compose_file }} down --volumes

# Tail logs from the dev stack. Trailing args go to `docker compose
# logs` (e.g. --follow, api).
[doc("Tail logs from the dev stack. Trailing args go to `docker compose logs` (e.g. api, --follow).")]
dev-logs *args:
    docker compose --file {{ compose_file }} logs {{ args }}

# Run all checks (compile, web/wasm, clippy, fmt)
check: check-compile check-web check-clippy check-fmt

# Check native compilation (bunyip-api + bunyip-mocks)
check-compile:
    cargo check --workspace --exclude bunyip-web --all-targets

# Check web/WASM compilation
check-web:
    cargo check --package bunyip-web --target wasm32-unknown-unknown

# Run clippy lints
check-clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Check formatting
check-fmt:
    cargo fmt --all --check

# Format code
fmt:
    cargo fmt --all

# Run tests (native only; wasm tests need a separate harness)
test:
    cargo test --workspace --exclude bunyip-web

# Build native release binaries (api + mocks)
build:
    cargo build --release --workspace --exclude bunyip-web

# Build the wasm SPA release bundle
build-web: css-build
    cd bunyip-web && dx build --release

# Validate seed JSON files parse
check-seeds:
    #!/usr/bin/env nu
    for f in (ls seeds/*.json | get name) {
        try { open $f | ignore; print $"OK: ($f)" } catch { print $"FAIL: ($f)"; exit 1 }
    }

# Build production OCI image for validation (api)
check-docker-api:
    docker buildx build --tag bunyip-api:check --file bunyip-api/oci-build/Dockerfile .

# Build production OCI image for validation (web)
check-docker-web:
    docker buildx build --tag bunyip-web:check --file bunyip-web/oci-build/Dockerfile .

# Build both production OCI images
build-docker: check-docker-api check-docker-web

# Create a release: bump version, push branch, print PR link
create-release bump:
    #!/usr/bin/env nu
    let bump = "{{ bump }}"

    let status = git status --porcelain | str trim
    if ($status | is-not-empty) {
        print $"(ansi red)Working tree is dirty. Please stash or commit your changes first.(ansi reset)"
        exit 1
    }

    let default_branch = "main"
    let branch = git branch --show-current | str trim
    if $branch != $default_branch {
        print $"Switching from ($branch) to ($default_branch)..."
        git checkout $default_branch
    }

    git pull --rebase origin $default_branch

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

    git checkout -b $release_branch
    open Cargo.toml | update workspace.package.version $bare | to toml | collect | save --force Cargo.toml
    git add Cargo.toml
    git commit --signoff --message $"Release ($tag)"

    git push --set-upstream origin $release_branch

    let remote = git remote get-url origin
    let base_url = if ($remote | str starts-with "ssh://") {
        $remote | str replace "ssh://git@" "https://" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    } else {
        $remote | str replace --regex "git@([^:]+):" "https://$1/" | str replace "git.a8n.run" "dev.a8n.run" | str replace ".git" ""
    }
    print $"(ansi green)Pushed ($release_branch)(ansi reset)"
    print $"Create PR: ($base_url)/compare/($default_branch)...($release_branch)"
    print $"After merging, the create-release workflow will tag and release ($tag) automatically."
