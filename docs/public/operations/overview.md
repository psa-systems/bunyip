# Operations

Running pages for an operator who is on the hook for bunyip in production. Short topic-per-page.

- [Backups](backups.md). What to copy, how often, and the one procedure that restores a running deployment.
- [Upgrades](upgrades.md). The release flow from the operator angle, including the migration-immutability guarantee that lets a rollforward be safe.
- [Host secrets](host-secrets.md). How an allow-listed machine client fetches a registry secret from bunyip without logging in as a user.
- [Rate limits](rate-limits.md). What `RateLimitFloor` caps, how to tune per-route, and when to allow-list a caller.
