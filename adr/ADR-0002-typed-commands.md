# ADR-0002: No shell strings; every command is a typed value

Status: accepted (2026-09-27)

## Context
An agent that can pass a string to a shell can do anything the account can.
Allowlisting by prefix ("allow `systemctl *`") is bypassed with `;`, `&&`,
`$()`, option injection (`--help`, `-o ...`) or newline smuggling.

## Decision
- `internal/exec` is the only package that starts processes. It takes an
  `exec.Command{ID, Bin, Args []Arg, Mutates}`; `Bin` must be on a fixed
  allowlist resolved from fixed absolute paths (PATH is never consulted).
- Arguments are `exec.Lit` (written by hostops) or `exec.Param` (derived from
  user input). Params are validated twice: by a typed validator in
  `internal/validate` (domain, unit, IP, jail, path-under-root) and again in
  `Command.Validate` for shell metacharacters and leading dashes.
- There is no command that accepts a free-form program or argument list.
- Tests: `internal/validate` injection corpus, `cmd/hostops/testdata/script/injection.txtar`,
  `internal/cli/cli_test.go` (newline/control characters in argv).

## Consequences
New capabilities need code, a validator and tests, which is slower than a
generic runner. That friction is the point.
