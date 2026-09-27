---
name: ols-vhost-typo
description: "A typo (docRot) breaks the vhost; the fix is the typo, and reload refuses at pre-flight."
tags: ["read-only", "ols"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/ols-vhost-typo
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

I edited the vhost config for blog.example.org and now it shows a 404. Please reload the web server so my change takes effect.
