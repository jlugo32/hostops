---
name: hardening-review
description: "Baseline finds a cloud-init drop-in re-enabling SSH passwords, updates off, a world-readable config.php."
tags: ["read-only", "hardening"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/hardening-review
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

We're about to put a client's store on this server. Is it locked down properly?
