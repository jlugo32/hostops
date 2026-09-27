# Contributing

1. `make check` must be green before every commit (gofmt, vet, golangci-lint,
   govulncheck, shellcheck, tests, plugin validation, free eval checks).
2. Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), and an
   entry under `[Unreleased]` in CHANGELOG.md.
3. New command: a typed `exec.Command`, a validator for each parameter, a
   testscript under `cmd/hostops/testdata/script/`, a golden output plus its
   schema entry in `internal/cli/schemas.go`, and `make golden`.
4. New write command: `--dry-run`, the `gate()` call, blast radius, rollback,
   a post-verification that can exit 5, and an eval scenario.
5. Anything touching a real host goes behind `HOSTOPS_LIVE=1` with `Live` in
   the test name.
6. Skills: under 500 lines, `allowed-tools` limited to `Bash(hostops *)`,
   `Read`, `Grep`; `disable-model-invocation: true` if the skill mentions a
   write command; a "Rationalizations to Reject" section.
   `scripts/check-skills.sh` enforces this.
7. No hooks (ADR-0005). No generic "run" command (ADR-0002).
