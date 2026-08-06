#!/bin/sh
#
# init-secrets.sh - bootstrap / migrate bunyip's file-based production secrets.
#
# Purpose:
#   compose.yml mounts every secret from a file under ./secrets/ (and the OIDC
#   signing keys from ./secrets/oidc/) rather than from environment variables,
#   so secrets never appear in `docker inspect` or /proc/<pid>/environ. This
#   script creates those files in one command, optionally migrating values out
#   of a legacy ./.env file, and leaves any value that is already in place
#   untouched (BUNYIP-38).
#
# Usage:
#   ./scripts/init-secrets.sh        (run from the repository root)
#
# Idempotency:
#   Safe to run repeatedly. A non-empty secret file is NEVER overwritten. An
#   existing empty file may be filled from a matching .env value, otherwise it
#   is left as-is. Re-running only fills the gaps.
#
# Requires: POSIX sh, openssl, and standard coreutils. No bashisms.

set -eu

SECRETS_DIR="./secrets"
OIDC_DIR="${SECRETS_DIR}/oidc"
ENV_FILE="./.env"

# Track whether postgres_password ended up generated so the summary can warn.
PG_GENERATED=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Read a single VAR= line from .env, strip one layer of surrounding single or
# double quotes, and echo the value. Echoes nothing if .env is absent or the
# var is not present. Last occurrence wins (tail -n 1).
read_env() {
    var="$1"
    [ -f "$ENV_FILE" ] || return 0
    line=$(grep "^${var}=" "$ENV_FILE" | tail -n 1) || true
    [ -n "$line" ] || return 0
    value=$(printf '%s' "$line" | cut -d= -f2-)
    # Strip matching surrounding quotes.
    case "$value" in
        \"*\") value=$(printf '%s' "$value" | sed 's/^"//; s/"$//') ;;
        \'*\') value=$(printf '%s' "$value" | sed "s/^'//; s/'\$//") ;;
    esac
    printf '%s' "$value"
}

# A value counts as "not set" when it is empty or a known dev placeholder.
is_set() {
    v="$1"
    [ -n "$v" ] || return 1
    case "$v" in
        dev-only-*)               return 1 ;;
        devpassword)              return 1 ;;
        changeme)                 return 1 ;;
        admin@bunyip.local:*)     return 1 ;;
        *)                        return 0 ;;
    esac
}

# True when a file exists and is non-empty.
has_content() {
    [ -s "$1" ]
}

# Write a value to a secret file with mode 600 and report it.
#   $1 = path, $2 = value, $3 = origin label (generated|from .env|empty)
# Honours idempotency: never clobbers a non-empty file.
write_secret() {
    path="$1"
    value="$2"
    origin="$3"
    if has_content "$path"; then
        printf 'kept %s\n' "$path"
        return 0
    fi
    # printf (no trailing newline) keeps the secret byte-exact.
    printf '%s' "$value" > "$path"
    chmod 600 "$path"
    printf 'created %s (%s)\n' "$path" "$origin"
}

# Resolve a secret from .env (when set) else generate via the given command.
#   $1 = path, $2 = env var name, $3 = generator command string
secret_from_env_or_gen() {
    path="$1"
    var="$2"
    gen="$3"
    if has_content "$path"; then
        printf 'kept %s\n' "$path"
        return 0
    fi
    val=$(read_env "$var")
    if is_set "$val"; then
        write_secret "$path" "$val" "from .env"
    else
        val=$(eval "$gen")
        write_secret "$path" "$val" "generated"
    fi
}

# Resolve a secret from .env (when set) else leave an empty file.
#   $1 = path, $2 = env var name
secret_from_env_or_empty() {
    path="$1"
    var="$2"
    if has_content "$path"; then
        printf 'kept %s\n' "$path"
        return 0
    fi
    val=$(read_env "$var")
    if is_set "$val"; then
        write_secret "$path" "$val" "from .env"
    else
        write_secret "$path" "" "empty"
    fi
}

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
mkdir -p "$OIDC_DIR"
chmod 700 "$OIDC_DIR"

# ---------------------------------------------------------------------------
# Plain secrets
# ---------------------------------------------------------------------------

secret_from_env_or_gen "${SECRETS_DIR}/jwt_secret"            JWT_SECRET            "openssl rand -hex 32"
secret_from_env_or_gen "${SECRETS_DIR}/totp_encryption_key"   TOTP_ENCRYPTION_KEY   "openssl rand -hex 32"
secret_from_env_or_gen "${SECRETS_DIR}/stripe_encryption_key" STRIPE_ENCRYPTION_KEY "openssl rand -hex 32"

# postgres_password MUST be non-empty: postgres refuses an empty password.
secret_from_env_or_gen "${SECRETS_DIR}/postgres_password"     POSTGRES_PASSWORD     "openssl rand -hex 32"
# Defensive: if an existing file was somehow empty, fill it so postgres starts.
if ! has_content "${SECRETS_DIR}/postgres_password"; then
    val=$(openssl rand -hex 32)
    printf '%s' "$val" > "${SECRETS_DIR}/postgres_password"
    chmod 600 "${SECRETS_DIR}/postgres_password"
    printf 'created %s (%s)\n' "${SECRETS_DIR}/postgres_password" "generated"
fi

# Note whether the password was generated (no usable .env value), for the
# rotation reminder below.
pg_env=$(read_env POSTGRES_PASSWORD)
if ! is_set "$pg_env"; then
    PG_GENERATED=1
fi

# database_url: prefer an explicit .env DATABASE_URL, else derive it from the
# postgres_password file so the two always agree. Derived AFTER the password
# exists.
DB_PATH="${SECRETS_DIR}/database_url"
if has_content "$DB_PATH"; then
    printf 'kept %s\n' "$DB_PATH"
else
    db_env=$(read_env DATABASE_URL)
    if is_set "$db_env"; then
        write_secret "$DB_PATH" "$db_env" "from .env"
    else
        pg_user=$(read_env POSTGRES_USER)
        is_set "$pg_user" || pg_user="bunyip"
        pg_db=$(read_env POSTGRES_DB)
        is_set "$pg_db" || pg_db="bunyip"
        pg_pass=$(cat "${SECRETS_DIR}/postgres_password")
        derived="postgres://${pg_user}:${pg_pass}@postgres:5432/${pg_db}"
        write_secret "$DB_PATH" "$derived" "generated"
    fi
fi

# Optional secrets: present in .env -> migrated, else an empty file which the
# api treats as "feature not configured".
secret_from_env_or_empty "${SECRETS_DIR}/setup_default_admin"  SETUP_DEFAULT_ADMIN
secret_from_env_or_empty "${SECRETS_DIR}/forgejo_api_token"    FORGEJO_API_TOKEN
secret_from_env_or_empty "${SECRETS_DIR}/smtp_password"        SMTP_PASSWORD
secret_from_env_or_empty "${SECRETS_DIR}/update_check_token"   BUNYIP_UPDATE_CHECK_TOKEN

# BUNYIP-482: no stripe_secret_key / stripe_webhook_secret files. The Stripe API
# keys live only in the stripe_config DB row (admin Stripe page), encrypted with
# stripe_encryption_key above.

# ---------------------------------------------------------------------------
# OIDC signing keys
# ---------------------------------------------------------------------------
# Dev convenience only: a single ed25519 keypair named dev-2026. Production
# operators should generate their own kid-named keys out-of-band (SOPS / deploy
# step) and drop the .pem / .pub.pem pair into ./secrets/oidc/.
OIDC_KEY="${OIDC_DIR}/dev-2026.pem"
OIDC_PUB="${OIDC_DIR}/dev-2026.pub.pem"
OLD_KEY="${SECRETS_DIR}/dev-2026.pem"
OLD_PUB="${SECRETS_DIR}/dev-2026.pub.pem"

if has_content "$OIDC_KEY"; then
    printf 'kept %s\n' "$OIDC_KEY"
    if has_content "$OIDC_PUB"; then
        printf 'kept %s\n' "$OIDC_PUB"
    fi
elif has_content "$OLD_KEY"; then
    # Migrate the legacy flat layout into ./secrets/oidc/.
    mv "$OLD_KEY" "$OIDC_KEY"
    chmod 600 "$OIDC_KEY"
    printf 'created %s (%s)\n' "$OIDC_KEY" "migrated"
    if has_content "$OLD_PUB"; then
        mv "$OLD_PUB" "$OIDC_PUB"
        chmod 600 "$OIDC_PUB"
        printf 'created %s (%s)\n' "$OIDC_PUB" "migrated"
    fi
else
    # Generate a fresh dev keypair.
    openssl genpkey -algorithm ed25519 -out "$OIDC_KEY"
    chmod 600 "$OIDC_KEY"
    printf 'created %s (%s)\n' "$OIDC_KEY" "generated"
    openssl pkey -in "$OIDC_KEY" -pubout -out "$OIDC_PUB"
    chmod 600 "$OIDC_PUB"
    printf 'created %s (%s)\n' "$OIDC_PUB" "generated"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf '\n'
printf 'Done. ./secrets/ is gitignored; key material is never committed.\n'
if [ "$PG_GENERATED" -eq 1 ]; then
    printf 'A random postgres_password was generated and database_url derived from it.\n'
fi
printf 'To rotate postgres_password, edit BOTH ./secrets/postgres_password AND\n'
printf './secrets/database_url so they stay consistent (or delete both files and\n'
printf 'rerun this script to regenerate a matching pair).\n'
