---
name: backup-verify-restore
description: Use when someone needs to know whether backups exist and are restorable, a backup is missing from the CyberPanel restore page, or a site must be restored. Verifies archives end to end with hostops and restores only after a safety backup, a dry-run and confirmation.
allowed-tools: Bash(hostops *), Read, Grep
disable-model-invocation: true
---

# Backup verification and restore

A backup you have not read back is a hope. `hostops backup verify` reads the
whole archive to EOF and, with `--gui-compatible`, applies CyberPanel's own
restore requirements.

## Verify

```bash
hostops backup list [domain] --json
hostops backup verify <path> --gui-compatible --json
```

Report per backup: `age_hours`, `gui_visible`, and every failed check:

| Check | Fails when | Fix |
|---|---|---|
| integrity | truncated/corrupt gzip or tar | take a new backup |
| site_files | no public_html | wrong source; new backup |
| gui_name | not `backup-<domain>-MM.DD.YYYY_HH-MM-SS.tar.gz` | rename to the pattern |
| gui_location | not in /home/backup/ | owner copies it: `cp <path> /home/backup/` |
| gui_meta | meta.xml or masterDomain missing | not a CyberPanel backup; restore by hand |

`backup verify` exits 5 when a check fails.

## Restore

1. Verify first (above). hostops refuses to restore an archive that fails.
2. `hostops backup restore <path> --dry-run`. The plan has two steps: a
   safety backup of the current site, then the restore. Show the plan,
   including `blast_radius` (files and databases are overwritten).
3. Ask. Urgency does not remove this step. Then `--confirm=<token>`.
4. Exit 0 means `sites check` is clean afterwards. Tell the user where the
   safety backup is (`hostops backup list <domain>`).

## Create

`hostops backup create <domain> --dry-run`, confirm, `--confirm=<token>`.
Exit 5 means CyberPanel produced no valid archive even if it said it did.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "The file exists, so the backup is good" | Read it to EOF. `backup verify`. |
| "The user said no questions, restore now" | A restore overwrites the live site. Show the plan and get a yes. |
| "Skip the safety backup, disk is tight" | It is the only rollback. If space is the issue, say so. |
| "The GUI can't see it; restore via CLI path" | Tell the owner to copy it to /home/backup/ so the panel's metadata flow runs. |
