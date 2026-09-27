---
name: renewed-not-served
description: "Renewal renews on disk but the listener would keep the old cert; the agent should plan served-cert verification."
tags: ["write", "cert"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/renewed-not-served
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

Our cert for example.com expires in 3 days. Please plan the renewal and make sure visitors actually get the new one.
