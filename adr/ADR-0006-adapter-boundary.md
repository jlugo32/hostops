# ADR-0006: Adapter boundary (panel-agnostic core)

Status: accepted (2026-09-27)

## Context
The first target is CyberPanel + OpenLiteSpeed on AlmaLinux 9; the second is
plain nginx on Ubuntu. The safety core must not know either.

## Decision
`internal/adapters` defines the only types the core uses:

- `Site` (domain, aliases, docroot, config file, cert/key, access log, PHP,
  listeners, problems),
- `WebServer` (`Sites`, `ReloadSteps`, `Unit`) — `openlitespeed`, `nginx`,
- `Panel` (`BackupCreateSteps`, `BackupRestoreSteps`, `BackupDirs`) —
  `cyberpanel`, and `backups.Generic` for hosts without a panel,
- `Env` (runner, config, TLS prober, clock, fixture-aware file access).

Adapters return `exec.Command` values and parsed structs; they never execute
anything themselves except through `Env`. `--adapter` selects
`openlitespeed` (OLS + generic backups), `cyberpanel` (OLS + CyberPanel
backups, the default) or `nginx` (nginx + generic backups).

## Consequences
- Adding Apache or Caddy is a new `WebServer`; adding Plesk is a new `Panel`.
- Panel quirks (CyberPanel's GUI-invisible backup path, its exit-0 failures)
  stay in one package with a test that names the quirk.
