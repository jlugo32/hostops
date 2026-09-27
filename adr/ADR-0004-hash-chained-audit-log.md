# ADR-0004: Hash-chained JSONL audit log

Status: accepted (2026-09-27)

## Context
After an incident the first question is "what did the agent run?". Shell
history is editable and incomplete.

## Decision
Every invocation appends one JSON line to
`$XDG_STATE_HOME/hostops/audit.jsonl` (default
`~/.local/state/hostops/audit.jsonl`): `ts`, `actor` (OS user + agent id from
`HOSTOPS_AGENT_ID` or `claude-code`), `command`, `argv`, `mode`
(live/fixture), `dry_run`, `confirm_token`, `exit_code`, `result_sha256`,
`prev_sha256`. `prev_sha256` is the sha256 of the previous line (64 zeros for
the first). Appends hold an exclusive `flock`. `hostops audit verify`
recomputes the chain and exits 5 at the first broken link.

Parameters are neutralized before writing: control characters, C1 codes,
bidi overrides and line separators become `\uXXXX`, and a record that would
span lines is refused, so a hostile parameter cannot forge a record.

A write command refuses to run (exit 2) if the log is not writable.

## Consequences
- Tamper-evident, not tamper-proof: root can rewrite the whole chain. Ship the
  head hash elsewhere (journal via the sidecar) for stronger guarantees.
- Reads are logged too; the file grows. Rotation must start a new chain file.
