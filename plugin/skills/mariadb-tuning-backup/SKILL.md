---
name: mariadb-tuning-backup
description: Use when pages are slow and the database is suspected, MariaDB will not start, a database is growing, or a site's data needs a backup. Reads slow-log fingerprints, sizes and unit state with hostops, proposes indexes or settings, and backs up only through dry-run and confirmation.
allowed-tools: Bash(hostops *), Read, Grep
disable-model-invocation: true
---

# MariaDB tuning and backup

## Slow pages

1. `hostops db slowlog --top 10 --json`. If `settings.enabled` is false, say
   so and give the owner `SET GLOBAL slow_query_log=1; SET GLOBAL long_query_time=1;`.
2. Rank by `total_sec`, not `max_sec`: one query run 40 times at 4 s hurts
   more than one 20 s report.
3. For the top fingerprint compare `rows_examined` with `rows_sent`. A ratio
   in the thousands means a missing index. Propose the index from the WHERE
   and ORDER BY columns, e.g.
   `ALTER TABLE orders ADD INDEX idx_email_created (customer_email, created_at);`
   and tell the owner to run `EXPLAIN` first and apply it off-peak (InnoDB
   builds online, but it still costs I/O).
4. `hostops db size --json` for context: `free_bytes` shows fragmentation.

A restart does not fix a slow query. Do not offer one for this symptom.

## MariaDB down

1. `hostops service status mariadb --json`: `result` tells how it died.
2. `hostops logs journal --unit mariadb --lines 100 --json`.
3. `errno 28` / "No space left on device" → disk is full; restarting cannot
   work until space is freed (see cyberpanel-ops for old backups). InnoDB
   crash recovery messages → let it finish; do not kill it.
4. Only when the cause is fixed: `hostops service restart mariadb --dry-run`,
   show the plan (every site using the database errors meanwhile), ask,
   `--confirm=<token>`.

## Backup

Site backups (`hostops backup create <domain>`) include the site's databases on
CyberPanel. Credentials come from `/root/.my.cnf`; never ask for or pass a
password on the command line.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "Restart MariaDB, it's slow" | Slowness is a query plan. Read the slow log. |
| "Service failed, restart it again" | Read why it failed. Disk full will fail every time. |
| "I'll run the ALTER myself" | hostops has no SQL write path. Propose it with EXPLAIN. |
| "Pass the password with -p to be quick" | Secrets never go on a command line; they end up in ps and logs. |

See references/tuning.md.
