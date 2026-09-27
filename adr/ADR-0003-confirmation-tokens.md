# ADR-0003: Confirmation-token protocol and exit code 4

Status: accepted (2026-09-27)

## Context
"Ask before destructive actions" in a prompt is advisory. We want the binary
to refuse a write unless the caller has seen the exact plan.

## Decision
1. Every write command supports `--dry-run`, which prints a `hostops.plan.v1`
   document: exact argv of each step, target, adapter, host, diff, blast
   radius, rollback, verification, and a `confirm_token`.
2. The token is `sha256("hostops-confirm-v1" || canonical plan JSON ||
   15-minute bucket)[:16]`. It is valid in its bucket and the next, so for
   15–30 minutes, and only for that plan on that host. If the state changes
   (a cert renewed, an IP already unbanned) the plan changes and the token
   dies.
3. Running the write without a valid token exits **4** and prints a
   `hostops.confirm.v1` envelope on stderr: the plan without a token, and
   `next_step` telling the caller to run `--dry-run`.
4. Tokens are single-use: the audit log is consulted and a token that already
   authorized an executed command is refused (`token_already_used`).

The binary cannot tell a human's approval from an agent approving itself; an
agent can read its own dry-run and pass the token. The plugin's skills and the
eval grader `confirm_requested` cover that half: the agent must stop and ask.

## Consequences
- The exit-4 envelope maps 1:1 onto an MCP "elicitation / multi-round-trip"
  request later: the envelope is the question, `--confirm` is the answer.
- Plans must be deterministic between dry-run and execution; nothing
  time-varying finer than an hour may appear in a plan.
