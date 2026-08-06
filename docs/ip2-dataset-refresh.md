# Refreshing the IP2Location / IP2Proxy datasets (BUNYIP-474)

bunyip reads two offline IP datasets, each an IP2Location LITE `.BIN`:

| Purpose | Env var | Installed file |
| --- | --- | --- |
| Login-country geoip (login-location alerts) | `IP2LOCATION_DB_PATH` | `IP2LOCATION-LITE-DB11.BIN` |
| ASN / VPN enrichment (abuse signal, BUNYIP-437) | `IP2PROXY_DB_PATH` | `IP2PROXY-LITE-PX11.BIN` |

The `ip2location` library never fetches these files; the deployment owns keeping them fresh. IP2Location LITE rebuilds **monthly**, so refresh on a monthly schedule. The library keeps the file's build date private, so freshness is judged from the file's mtime: the admin dashboard **Datasets** card shows each file's age and flags one older than 40 days as `Stale`, so a missed refresh is visible without reading logs.

## One-off / scheduled refresh

`scripts/refresh-ip2-datasets.nu` downloads and installs both files atomically. It needs `nu`, `curl`, `unzip`, and a free IP2Location download token (create an account at ip2location.com; the token is on the account's download page).

```nu
IP2LOCATION_TOKEN=<token> DATASET_DIR=/data ./scripts/refresh-ip2-datasets.nu
```

- `DATASET_DIR` (default `/data`) is where the `.BIN` files are written. Point `IP2LOCATION_DB_PATH` at `$DATASET_DIR/IP2LOCATION-LITE-DB11.BIN` and `IP2PROXY_DB_PATH` at `$DATASET_DIR/IP2PROXY-LITE-PX11.BIN`.
- `DATASETS` (default `PX11 DB11`) selects which datasets to refresh, e.g. `DATASETS=PX11` for enrichment only.
- Each file is staged in `DATASET_DIR` and renamed into place, so a partial download never replaces a good file and the running api never reads a half-written `.BIN`. The script exits non-zero if any dataset fails, so a scheduler surfaces the failure.

The token is a secret: pass it from the deployment's secret store (an env file, a compose/Kubernetes secret, or the scheduler's secret mechanism), never commit it.

## Scheduling it

Run the script once a month. On a host with the repo checked out and the token in an env file:

```
# /etc/cron.d/bunyip-ip2-refresh  -  05:00 on the 3rd of each month (after IP2Location's monthly rebuild)
0 5 3 * * deploy  . /etc/bunyip/ip2.env && DATASET_DIR=/data /opt/bunyip/scripts/refresh-ip2-datasets.nu >> /var/log/bunyip-ip2-refresh.log 2>&1
```

`/etc/bunyip/ip2.env` holds `IP2LOCATION_TOKEN=...` (mode 0600). The same command works as a systemd timer, a Kubernetes CronJob, or any scheduler: it is a plain script with a non-zero exit on failure. The scheduler's environment needs `nu` on `PATH` (the script's shebang is `#!/usr/bin/env nu`); cron's minimal `PATH` often does not include `/usr/local/bin`, so set it in the crontab or invoke the script as `nu /opt/bunyip/scripts/refresh-ip2-datasets.nu`.

If the app runs from `compose.yml`, point `DATASET_DIR` at the host directory the api bind-mounts for `/data`, so a refresh on the host is picked up by the container (the api opens the `.BIN` at startup; restart it, or let the next deploy pick up the newer file, to load a fresh dataset - the enrichment/geoip lookups themselves always read the file that was open at boot).
