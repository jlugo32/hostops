---
name: cyberpanel-ops
description: Use when working on a CyberPanel host: site inventory, the CyberPanel CLI, backups the GUI cannot see, or anything where CyberPanel reports success but nothing happened. Routes every action through hostops so panel quirks are checked and writes are confirmed.
allowed-tools: Bash(hostops *), Read, Grep
disable-model-invocation: true
---

# CyberPanel operations

CyberPanel wraps OpenLiteSpeed, acme.sh, Postfix/Dovecot and MariaDB. Its CLI
and cron jobs often exit 0 or log "SUCCESSFUL" on failure, so hostops verifies
outcomes instead of trusting exit codes.

## Inventory

```bash
hostops sites list --json      # from OLS config: docroot, PHP, aliases, listeners
hostops sites check --json     # problems per site, cert days left
hostops backup list --json     # every backup, age, gui_visible
hostops service status lsws    # web server
hostops service status mariadb
```

Site files live in `/home/<domain>/public_html/`; logs in `/home/<domain>/logs/`.

## Known quirks hostops encodes

| Quirk | hostops behaviour |
|---|---|
| `cyberpanel createBackup` defaults to `/home/<domain>/backup/`, invisible to the GUI restore page | `backup create` writes to `/home/backup/` |
| The CLI prints `0` and exits 0 on failure | `backup create` exits 5 unless a new, valid archive appears |
| Restore extracts over the live site | `backup restore` verifies the archive, then takes a safety backup first |
| Renew cron logs success on failed issuance | `cert renew` compares the served certificate (see cert-renewal-verify) |

## Writes

`backup create <domain>`, `backup restore <path>`, `sites reload`,
`cert renew <domain>`: each needs `--dry-run`, the plan shown to the user, an
explicit yes, then `--confirm=<token>`. Exit 4 means you skipped that.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "The panel said SUCCESSFUL" | Check the artefact: the file, the served cert, the unit state. |
| "I'll use the cyberpanel CLI directly, it's simpler" | Then nothing verifies it and nothing is audited. Use hostops. |
| "The backup exists, so the GUI can restore it" | Only files in /home/backup/ are listed. Run `backup verify --gui-compatible`. |
| "Deleting old backups frees space, just do it" | hostops has no delete by design. Recommend it; the owner deletes. |

See references/cyberpanel-layout.md.
