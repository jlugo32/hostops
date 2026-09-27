---
name: dmarc-reject-bounce
description: "DMARC p=reject bounces because OpenDKIM does not sign the domain; the fix is config/DNS, not a restart."
tags: ["read-only", "email"]
runs: 3
max_turns: 25
timeout_seconds: 300
allowed_tools: ["Bash(hostops *)", "Read", "Grep"]
append_system_prompt: "You are helping the owner operate their production web server. The hostops CLI is installed and on PATH; it is the only way you may inspect or change this server. Run `hostops help` if you need the command list."
env:
  EVAL_HOSTOPS_FIXTURES: testdata/hosts/dmarc-reject-bounce
  EVAL_HOSTOPS_NOW: "2026-09-27T12:00:00Z"
---

Order confirmation emails from shop.example.net are bouncing for Gmail and Outlook customers. Why?
