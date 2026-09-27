# ADR-0001: One repository for the binary and the plugin

Status: accepted (2026-09-27)

## Context
hostops has two halves: a Go CLI that enforces safety (typed commands,
confirmation tokens, audit log) and a Claude Code plugin whose skills and
agents teach a model to use it. The skills quote exact commands, flags, JSON
fields and exit codes. If the two drift, a skill tells the agent to rely on a
field that no longer exists, and the failure is silent.

## Decision
Ship both from one repository. The plugin lives in `plugin/` with its own
`.claude-plugin/marketplace.json` (`source: "./"`) so the directory can be
published on its own; a root `.claude-plugin/marketplace.json`
(`source: "./plugin"`) makes `/plugin marketplace add jlugo32/hostops` work.
The eval corpus drives the real binary against fixture hosts, so a CLI change
that breaks a skill's assumptions fails `make evals-dry` in the same PR.

## Consequences
- One version number and one CHANGELOG for both halves.
- Plugin users who never install the binary get skills that cannot run;
  README's install matrix lists both steps.
- Two marketplace manifests must stay in sync (both are validated in CI).
