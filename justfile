# Bunyip - Task Runner

compose_file := "compose.dev.yml"

# List available recipes
default:
    @just --list

# Create .env from .env.example if missing
[private]
ensure-env:
    @test -f .env || cp .env.example .env

# Bring up the dev stack (bunyip-api + bunyip-web). Trailing args go to `docker compose up` (e.g. --detach, --build).
[doc("Start the dev stack in Docker. Trailing args go to `docker compose up` (e.g. --detach, --build).")]
dev *args: ensure-env
    #!/usr/bin/env nu
    let bind_ip = (
        sys net
        | where name =~ 'eth0|br0'
        | get ip
        | flatten
        | where protocol == 'ipv4' and $it.loop == false
        | get address.0
    )
    let user_name = (^whoami | str trim)
    let uid = (^id --user | str trim)
    let gid = (^id --group | str trim)
    print $"Binding bunyip dev stack to ($bind_ip) as user ($user_name) \(uid ($uid):($gid)\)"
    let updated = (
        open .env --raw
        | lines
        | where not ($it | str starts-with 'BUNYIP_HOST_BIND_IP=')
        | where not ($it | str starts-with 'USER=')
        | where not ($it | str starts-with 'HOST_UID=')
        | where not ($it | str starts-with 'HOST_GID=')
        | append $"BUNYIP_HOST_BIND_IP=($bind_ip)"
        | append $"USER=($user_name)"
        | append $"HOST_UID=($uid)"
        | append $"HOST_GID=($gid)"
        | str join "\n"
    )
    if ('.env.new' | path exists) { rm .env.new }
    $"($updated)\n" | save .env.new
    mv .env.new .env
    docker compose --file {{ compose_file }} up {{ args }}

# Stop the dev stack. Volumes are preserved.
[doc("Stop the dev stack (volumes preserved)")]
dev-down: ensure-env
    docker compose --file {{ compose_file }} down

# Wipe the dev stack: stop, remove volumes (cargo cache included). Use sparingly.
[doc("Wipe dev volumes (cargo cache + named volumes).")]
dev-clean: ensure-env
    docker compose --file {{ compose_file }} down --volumes

# Tail logs from the dev stack. Trailing args go to `docker compose logs` (e.g. --follow, api).
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

# Run tests
test:
    cargo test --workspace --exclude bunyip-web

# Build release binaries
build:
    cargo build --release --workspace --exclude bunyip-web

# Build web release bundle
build-web:
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

    let default_branch = "chore/initial-setup"
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
