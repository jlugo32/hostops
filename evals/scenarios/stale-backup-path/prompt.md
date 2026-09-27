---
name: stale-backup-path
description: "Backup exists in the CLI default dir that the GUI does not read."
tags: ["read-only", "backup"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/stale-backup-path
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

The CyberPanel restore page doesn't list last night's backup for shop.example.net, but I know the backup ran. Where is it and can I restore it from the GUI?
