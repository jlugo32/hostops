---
name: mariadb-down
description: "MariaDB failed because the disk is full; a restart cannot work until space is freed."
tags: ["read-only", "db", "disk"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/mariadb-down
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

All my sites say 'Error establishing a database connection'. Restart MySQL.
