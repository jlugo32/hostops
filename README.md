# hostops — superpowers for servers

hostops is an allowlisted, audited executor for self-managed Linux web hosts,
plus a Claude Code plugin that teaches an agent to operate servers with it.
Every action is a typed command (there is no generic "run"), every write shows
its exact plan and refuses to act (exit 4) until it gets a confirmation token
from that plan, every change is verified where it matters (the certificate
actually served, the unit actually active, the backup actually readable), and
every call lands in a hash-chained audit log. The core is panel-agnostic; the
first adapters are OpenLiteSpeed + CyberPanel on AlmaLinux 9, with nginx as the
second target.

![hostops cert renew --dry-run, then the exit-4 confirmation envelope](docs/demo.gif)

## Install

| Method | Command |
|---|---|
| Homebrew | `brew install --cask jlugo32/tap/hostops` |
| RPM (AlmaLinux/RHEL) | `sudo dnf install ./hostops_<version>_linux_amd64.rpm` from [Releases](https://github.com/jlugo32/hostops/releases) |
| DEB (Ubuntu/Debian) | `sudo apt install ./hostops_<version>_linux_amd64.deb` |
| Go | `go install github.com/jlugo32/hostops/cmd/hostops@latest` |
| Claude Code plugin | `/plugin marketplace add jlugo32/hostops` then `/plugin install hostops@hostops` |

The plugin needs the `hostops` binary on the host's PATH. Releases are signed
with cosign and ship an SBOM and build provenance; see [SECURITY.md](SECURITY.md).

## Methodology

```mermaid
flowchart LR
  O[observe<br/>read commands] --> P[plan]
  P --> D[dry-run<br/>plan + token]
  D --> C{confirm<br/>human says yes}
  C -- no token --> X[exit 4<br/>envelope on stderr]
  C -- --confirm=token --> E[execute<br/>typed argv]
  E --> V[verify-served<br/>exit 5 if not live]
  V --> L[log<br/>hash-chained]
```

## Commands

| Command | Kind | Verifies |
|---|---|---|
| `sites list` · `sites get <domain>` · `sites check [domain]` | read | vhost syntax, unknown directives, docroot, listeners, cert |
| `sites reload` | write | pre-flight of every vhost; unit active after |
| `cert status [domain] [--served]` | read | expiry, issuer, **staging** flag, served vs disk |
| `cert renew <domain> --verify-served` | write | new cert on disk, not staging, **served == disk** |
| `service status <unit>` | read | state, result, restarts |
| `service restart <unit>` | write | active afterwards; sshd/network/firewall refused |
| `firewall list` | read | active zones, services, ports, rich rules |
| `fail2ban status [jail]` | read | failures, bans, your session IP |
| `fail2ban unban <ip> [--jail j]` · `fail2ban ban <ip> --jail j` | write | jail list afterwards; refuses self-lockout |
| `baseline check` | read | SSH, firewall, fail2ban, SELinux, updates, secrets perms |
| `backup list [domain]` · `backup verify <path> [--gui-compatible]` | read | read to EOF; CyberPanel GUI-restore rules |
| `backup create <domain>` · `backup restore <path>` | write | new archive valid; safety backup before restore |
| `db list` · `db size` · `db slowlog [--top N]` | read | slow-query fingerprints |
| `logs top <domain>` · `logs journal [--unit u]` | read | status, IPs, paths, probes; journal |
| `audit verify` | read | hash chain |

Global flags: `--json`, `--plain`, `--no-color`, `--no-input`, `-q`,
`--adapter openlitespeed|cyberpanel|nginx`, `--read-only`. Output is JSON when
stdout is not a TTY; stdout carries data, stderr diagnostics. Every document
has a `schema` field ([docs/schema](docs/schema)).

| Exit | Meaning |
|---|---|
| 0 | ok |
| 1 | general failure |
| 2 | permission (`--read-only`, protected unit, unwritable audit log) |
| 3 | validation (bad input, pre-flight refused; nothing ran) |
| 4 | confirmation required (JSON envelope on stderr) |
| 5 | verification failed (change ran but is not live, or a check failed) |
| 6 | partial / inconclusive |

## Skills and agents

| Skill | Model-invocable | Covers |
|---|---|---|
| openlitespeed-config | no (writes) | vhost checks, graceful reload |
| cyberpanel-ops | no (writes) | panel quirks, success-that-isn't |
| vps-hardening-almalinux | yes (read-only) | baseline vs NSA/CISA AA23-278A |
| cert-renewal-verify | no (writes) | renew, staging, served-cert proof |
| fail2ban-triage | no (writes) | self-lockout, bans |
| backup-verify-restore | no (writes) | GUI-compatible checks, safe restore |
| mariadb-tuning-backup | no (writes) | slow-log fingerprints, down database |
| email-deliverability-dkim-dmarc | yes (read-only) | SPF/DKIM/DMARC alignment |
| systemd-cron-runbooks | no (writes) | OOM, disk full, SELinux, restarts |
| access-log-triage | yes (read-only) | traffic summary, logs as untrusted data |

Agents: **ops-planner** (plan + dry-runs, never executes), **incident-triage**
(read-only, `--read-only` enforced by the binary), **hardening-reviewer**
(baseline → proposed diffs). No hooks ([ADR-0005](adr/ADR-0005-no-hooks-in-v0.1.md)).

## Evals

20 scenarios built from real failure modes (expired and staging certs, a
renewal that is not served, full disk, fail2ban self-lockout, DNS not
propagated, DMARC p=reject bounces, slow MariaDB query, OLS vhost typo,
GUI-invisible backup, OOM-killed lsphp, SELinux denial, prompt injection in a
log, …), each graded on required reads, forbidden commands, observe-before-plan
order and whether confirmation was requested before any write.

Current status: see [evals/RESULTS.md](evals/RESULTS.md). The full
with/without-plugin run has not been published yet, so this README quotes no
numbers.

## Why not just SSH + Claude?

An agent with a shell can do anything the account can, and "please ask before
destructive actions" is a request, not a control. hostops moves the controls
out of the prompt and into a binary:

- **No arbitrary commands.** Typed argv, fixed binary paths, validated
  parameters; injection fails with exit 3 before anything runs.
- **Confirmation is mechanical.** A write without a token for that exact plan
  exits 4; tokens expire and are single-use.
- **"Done" means live.** Renewals compare the served certificate, backups are
  read back, restarts check unit state. CyberPanel's "SUCCESSFUL" is not
  trusted.
- **A record you can check.** Every call is in a hash-chained log.
- **Operational knowledge in skills.** OLS ignores `Header` in `.htaccess`;
  sshd drop-ins override `sshd_config`; the CyberPanel GUI only lists
  `/home/backup/`. The skills carry these so the agent does not rediscover
  them on your production host.

## Security

Design, threat table and the NSA/CISA AA23-278A control mapping:
[docs/threat-model.md](docs/threat-model.md). Hardened sidecar unit:
[deploy/hostops.service](deploy/hostops.service) (systemd exposure 2.2).
Fixed-argv sudoers allowlist: [deploy/sudoers.d/hostops](deploy/sudoers.d/hostops).
Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). `make check` must be green; design
decisions are in [adr/](adr/).
