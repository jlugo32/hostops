# hostops — working rules for Claude Code

- Dev path: `/root/projects/hostops/`. Live target: `31.97.43.170` (AlmaLinux 9,
  CyberPanel, OpenLiteSpeed, PHP 8.5, MariaDB). Sites live in
  `/home/<domain>/public_html/` and deploy with `deploy-site <name> <domain>`.
- Tests never need a live server. Anything that touches a real host runs only
  under `HOSTOPS_LIVE=1`, and its test name contains `Live`
  (`make test-live`).
- **Never run a write command against the live host without a `--dry-run`
  first and then `--confirm=<token>`**, and only after the owner approved that
  exact plan in the conversation.

## Methodology

observe → plan → dry-run → confirm → execute → verify-served → log

## Exit-code contract

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | general failure |
| 2 | auth/permission (incl. `--read-only`, protected units, unwritable audit log) |
| 3 | validation (bad input, pre-flight refused; nothing ran) |
| 4 | confirmation required (JSON envelope on stderr) |
| 5 | verification failed (change ran but is not live, or a check failed) |
| 6 | partial / inconclusive |

## Commands

- `make check` before every commit (lint, test, validate, evals-dry). Do not
  proceed on red.
- `claude plugin validate --strict plugin/` must pass (`make validate`).
- `make golden` after an intended output change; review the diff.
- `go run ./internal/testhost/genfixtures -out testdata/hosts` regenerates
  fake hosts (then `make golden`).
- `make evals` is paid (runs the agent); `make evals-dry` is free.

## Code rules

- No catch-all `run`/`exec`/`shell` command, ever. Every process is an
  `exec.Command` with an explicit argv; user values go through
  `internal/validate` and `exec.Param`.
- stdout is data, stderr is diagnostics. Every JSON document has `schema`;
  new output types go into `internal/cli/schemas.go`.
- Secrets never via flags. Numbers in README come only from a committed
  `evals/RESULTS.md` or a CI benchmark.
- Conventional commits; keep `CHANGELOG.md` (Keep a Changelog) current.
