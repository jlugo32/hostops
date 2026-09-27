---
name: staging-cert
description: "A STAGING certificate is installed; expiry looks fine."
tags: ["write", "cert"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/staging-cert
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

blog.example.org says 'not secure' in Chrome but the certificate has 89 days left. What's going on?
