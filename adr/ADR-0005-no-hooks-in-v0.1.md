# ADR-0005: No hooks in v0.1

Status: accepted (2026-09-27)

## Context
Claude Code plugins can ship hooks: shell commands that run automatically on
events (session start, before/after tool use) with the user's privileges.
Published proof-of-concept attacks against coding agents follow a common
pattern: content the agent processes, or a component it loads, gets code to
run that rewrites the agent's own settings (permission allowlists, hooks), so
that later tool calls run without prompts. A plugin hook is the most direct
way to land such a change: it executes without a model decision and survives
across sessions.

## Decision
`plugin/hooks/` is empty in v0.1 (a README explains why), and CI fails if a
file appears there. All safety lives in the hostops binary, which neither a
prompt nor a plugin update can switch off: typed commands, exit-4
confirmation, single-use tokens, `--read-only`, the audit log.

## Consequences
- No automatic "log every Bash call" or "block raw systemctl" hook. The
  skills restrict themselves to `allowed-tools: Bash(hostops *)` instead,
  and the evals measure whether agents stay inside it.
- Revisit when hooks can be scoped and signed, and only for read-only
  observers.
