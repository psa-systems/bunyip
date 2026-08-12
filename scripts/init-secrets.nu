#!/usr/bin/env nu

# init-secrets.nu - bootstrap / migrate bunyip's file-based production secrets.
#
# Purpose:
#   compose.yml mounts every secret from a file under ./secrets/ (and the OIDC
#   signing keys from ./secrets/oidc/) rather than from environment variables,
#   so secrets never appear in `docker inspect` or /proc/<pid>/environ. This
#   script creates those files in one command, optionally migrating values out
#   of a legacy ./.env file, and leaves any value that is already in place
#   untouched (BUNYIP-38).
#
#   This is the DEV-BOX path: the values it generates are local throwaways. On a
#   deployment the same secret files are provided directly (the SOPS
#   compose-secrets.yml on the docker hosts). Group-1 secrets are never fetched
#   from or synced with Infisical; only Group-2 integration secrets use Infisical
#   (see docs/secrets-infisical.md).
#
# Usage:
#   ./scripts/init-secrets.nu        (run from the repository root)
#
# Idempotency:
#   Safe to run repeatedly. A non-empty secret file is NEVER overwritten. An
#   existing empty file may be filled from a matching .env value, otherwise it
#   is left as-is. Re-running only fills the gaps.
#
# Requires: nu, openssl, chmod.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# True when a file exists and is non-empty.
def has-content [path: string]: nothing -> bool {
    if ($path | path type) != "file" { return false }
    (ls $path | get 0.size) > 0b
}

# Read a single VAR= line from .env, strip one layer of surrounding single or
# double quotes, and return the value. Returns "" if .env is absent or the var
# is not present. Last occurrence wins.
def read-env [env_file: string, var: string]: nothing -> string {
    if ($env_file | path type) != "file" { return "" }
    let matched = (
        try { open --raw $env_file | decode utf-8 | lines } catch { [] }
        | where {|line| $line | str starts-with $"($var)=" }
    )
    if ($matched | is-empty) { return "" }
    # Everything after the first '=' is the value.
    let value = ($matched | last | split row "=" | skip 1 | str join "=")
    if ($value | str starts-with '"') and ($value | str ends-with '"') {
        $value | str replace --regex '^"' "" | str replace --regex '"$' ""
    } else if ($value | str starts-with "'") and ($value | str ends-with "'") {
        $value | str replace --regex "^'" "" | str replace --regex "'$" ""
    } else {
        $value
    }
}

# A value counts as "not set" when it is empty or a known dev placeholder.
def is-set [value: string]: nothing -> bool {
    if ($value | is-empty) { return false }
    if ($value | str starts-with "dev-only-") { return false }
    if $value in ["devpassword" "changeme"] { return false }
    if ($value | str starts-with "admin@bunyip.local:") { return false }
    true
}

# Write a value to a secret file with mode 600 and report it. Honours
# idempotency: never clobbers a non-empty file.
def write-secret [path: string, value: string, origin: string] {
    if (has-content $path) {
        print $"kept ($path)"
        return
    }
    # `save --raw` keeps the secret byte-exact (no trailing newline). The file
    # is empty when it exists at all, so dropping it first avoids a force write.
    if ($path | path type) == "file" { rm $path }
    $value | save --raw $path
    ^chmod 600 $path
    print $"created ($path) \(($origin))"
}

# Resolve a secret from .env (when set) else generate it with `gen`.
def secret-from-env-or-gen [path: string, env_file: string, var: string, gen: closure] {
    if (has-content $path) {
        print $"kept ($path)"
        return
    }
    let value = (read-env $env_file $var)
    if (is-set $value) {
        write-secret $path $value "from .env"
    } else {
        write-secret $path (do $gen) "generated"
    }
}

# Resolve a secret from .env (when set) else leave an empty file.
def secret-from-env-or-empty [path: string, env_file: string, var: string] {
    if (has-content $path) {
        print $"kept ($path)"
        return
    }
    let value = (read-env $env_file $var)
    if (is-set $value) {
        write-secret $path $value "from .env"
    } else {
        write-secret $path "" "empty"
    }
}

def main [] {
    let secrets_dir = "./secrets"
    let oidc_dir = $"($secrets_dir)/oidc"
    let env_file = "./.env"
    let gen_hex = {|| ^openssl rand -hex 32 | str trim }

    # -----------------------------------------------------------------------
    # Directories
    # -----------------------------------------------------------------------

    mkdir $secrets_dir
    ^chmod 700 $secrets_dir
    mkdir $oidc_dir
    ^chmod 700 $oidc_dir

    # -----------------------------------------------------------------------
    # Plain secrets
    # -----------------------------------------------------------------------

    secret-from-env-or-gen $"($secrets_dir)/jwt_secret" $env_file "JWT_SECRET" $gen_hex
    # BUNYIP-483: ONE at-rest key for the TOTP, Stripe and SMTP secrets.
    secret-from-env-or-gen $"($secrets_dir)/app_encryption_key" $env_file "APP_ENCRYPTION_KEY" $gen_hex

    # postgres_password MUST be non-empty: postgres refuses an empty password.
    let pg_path = $"($secrets_dir)/postgres_password"
    secret-from-env-or-gen $pg_path $env_file "POSTGRES_PASSWORD" $gen_hex
    # Defensive: if an existing file was somehow empty, fill it so postgres starts.
    if not (has-content $pg_path) {
        write-secret $pg_path (do $gen_hex) "generated"
    }

    # Note whether the password was generated (no usable .env value), for the
    # rotation reminder below.
    let pg_generated = not (is-set (read-env $env_file "POSTGRES_PASSWORD"))

    # database_url: prefer an explicit .env DATABASE_URL, else derive it from the
    # postgres_password file so the two always agree. Derived AFTER the password
    # exists.
    let db_path = $"($secrets_dir)/database_url"
    if (has-content $db_path) {
        print $"kept ($db_path)"
    } else {
        let db_env = (read-env $env_file "DATABASE_URL")
        if (is-set $db_env) {
            write-secret $db_path $db_env "from .env"
        } else {
            let user_env = (read-env $env_file "POSTGRES_USER")
            let pg_user = (if (is-set $user_env) { $user_env } else { "bunyip" })
            let db_env_name = (read-env $env_file "POSTGRES_DB")
            let pg_db = (if (is-set $db_env_name) { $db_env_name } else { "bunyip" })
            let pg_pass = (open --raw $pg_path | decode utf-8)
            write-secret $db_path $"postgres://($pg_user):($pg_pass)@postgres:5432/($pg_db)" "generated"
        }
    }

    # Optional secrets: present in .env -> migrated, else an empty file which the
    # api treats as "feature not configured".
    secret-from-env-or-empty $"($secrets_dir)/setup_default_admin" $env_file "SETUP_DEFAULT_ADMIN"
    secret-from-env-or-empty $"($secrets_dir)/forgejo_api_token" $env_file "FORGEJO_API_TOKEN"
    secret-from-env-or-empty $"($secrets_dir)/update_check_token" $env_file "BUNYIP_UPDATE_CHECK_TOKEN"

    # BUNYIP-482: no stripe_secret_key / stripe_webhook_secret files. The Stripe
    # API keys live only in the stripe_config DB row (admin Stripe page),
    # encrypted with app_encryption_key above.

    # -----------------------------------------------------------------------
    # OIDC signing keys
    # -----------------------------------------------------------------------
    # Dev convenience only: a single ed25519 keypair named dev-2026. Production
    # operators should generate their own kid-named keys out-of-band (SOPS /
    # deploy step) and drop the .pem / .pub.pem pair into ./secrets/oidc/.
    let oidc_key = $"($oidc_dir)/dev-2026.pem"
    let oidc_pub = $"($oidc_dir)/dev-2026.pub.pem"
    let old_key = $"($secrets_dir)/dev-2026.pem"
    let old_pub = $"($secrets_dir)/dev-2026.pub.pem"

    if (has-content $oidc_key) {
        print $"kept ($oidc_key)"
        if (has-content $oidc_pub) {
            print $"kept ($oidc_pub)"
        }
    } else if (has-content $old_key) {
        # Migrate the legacy flat layout into ./secrets/oidc/. The destination is
        # empty when it exists at all, so dropping it first avoids a force move.
        if ($oidc_key | path type) == "file" { rm $oidc_key }
        mv $old_key $oidc_key
        ^chmod 600 $oidc_key
        print $"created ($oidc_key) \(migrated)"
        if (has-content $old_pub) {
            if ($oidc_pub | path type) == "file" { rm $oidc_pub }
            mv $old_pub $oidc_pub
            ^chmod 600 $oidc_pub
            print $"created ($oidc_pub) \(migrated)"
        }
    } else {
        # Generate a fresh dev keypair.
        if ($oidc_key | path type) == "file" { rm $oidc_key }
        ^openssl genpkey -algorithm ed25519 -out $oidc_key
        ^chmod 600 $oidc_key
        print $"created ($oidc_key) \(generated)"
        if ($oidc_pub | path type) == "file" { rm $oidc_pub }
        ^openssl pkey -in $oidc_key -pubout -out $oidc_pub
        ^chmod 600 $oidc_pub
        print $"created ($oidc_pub) \(generated)"
    }

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print ""
    print "Done. ./secrets/ is gitignored; key material is never committed."
    if $pg_generated {
        print "A random postgres_password was generated and database_url derived from it."
    }
    print "To rotate postgres_password, edit BOTH ./secrets/postgres_password AND"
    print "./secrets/database_url so they stay consistent (or delete both files and"
    print "rerun this script to regenerate a matching pair)."
}
