# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-27

### Added
- `hostops` CLI: 16 read and 7 write commands over typed, allowlisted
  commands; no generic runner.
- Confirmation protocol: `--dry-run` plans with plan-bound, expiring,
  single-use tokens; exit 4 envelope on stderr.
- Hash-chained JSONL audit log with `hostops audit verify`.
- Adapters: OpenLiteSpeed, CyberPanel, nginx, systemd, fail2ban, firewalld,
  certificates (staging detection, served-cert probe), MariaDB, backups
  (CyberPanel GUI-compatibility checks), access logs.
- `pkg/accesslog`: OLS/nginx/Apache/Caddy parser, standard library only.
- Output contract: JSON when not a TTY, `--plain`, `NO_COLOR`, 20 JSON
  schemas generated from the Go types.
- Claude Code plugin: 10 skills, 3 agents, no hooks.
- Eval corpus: 20 failure-mode scenarios over generated fixture hosts, with
  a headless with/without-plugin runner.
- Hardened systemd sidecar unit and timer, fixed-argv sudoers allowlist and
  per-domain generator.
- CI (Linux, macOS, AlmaLinux 9 container), plugin validation, OpenSSF
  Scorecard, tag-triggered signed releases with SBOM, rpm/deb and Homebrew.

[Unreleased]: https://github.com/jlugo32/hostops/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jlugo32/hostops/releases/tag/v0.1.0
