---
name: cert-renewal-verify
description: Use when a TLS certificate is expired, expiring, from a Let's Encrypt STAGING issuer, or was renewed but visitors still see the old one. Diagnoses with hostops, renews through dry-run and user confirmation, and proves the new certificate is actually served.
allowed-tools: Bash(hostops *), Read, Grep
disable-model-invocation: true
---

# Certificate renewal with served-cert verification

A renewal is done when the web server **serves** the new certificate, not when
the ACME client prints "success". CyberPanel's renew cron has logged success on
failed issuance, and a renewed file on disk means nothing until the listener
reloads it.

## Protocol

1. **Observe** (read-only, no confirmation needed):
   ```bash
   hostops cert status <domain> --served --json
   hostops sites check <domain> --json
   ```
   Record `days_left`, `issuer`, `staging`, `served_matches_disk`.
2. **Classify** using the table below before proposing anything.
3. **Plan**: `hostops cert renew <domain> --dry-run --json`. Show the user the
   `steps[].argv`, `dry_run_diff`, `blast_radius` and `rollback` verbatim.
4. **Confirm**: stop and ask the user. Only after an explicit yes run
   `hostops cert renew <domain> --confirm=<token>`. Never reuse a token, never
   invent one, never pass `--confirm` in the same turn you first showed the plan.
5. **Verify**: exit 0 means disk renewed, not staging, and the served cert
   equals the disk cert. Exit 5 means the change ran but is not live: report it
   as a failure and go to "Renewed but not served".
6. **Log**: every call is in the hash-chained audit log; mention
   `hostops audit verify` if the user asks what changed.

| Observation | Meaning | Action |
|---|---|---|
| `days_left` < 0 | expired | renew |
| `staging: true` | browsers reject it even with 89 days left | renew; the plan forces the production CA |
| disk fine, `served_matches_disk: false` | listener holds an old copy | `hostops sites reload` (dry-run + confirm) |
| no renewal config | never issued by acme.sh/certbot | tell the user to issue it (CyberPanel: SSL → Manage SSL) |
| cert fine, site still wrong | DNS or CDN, not the server | do not renew; see references/diagnosis.md |

## Exit codes

0 ok · 3 bad input or no renewal config · 4 needs `--confirm` (read the
envelope on stderr) · 5 renewed but verification failed · 6 renewed, served
cert not checked (`--verify-served=false`).

## Renewed but not served (exit 5)

Do not re-run renew: Let's Encrypt allows 5 duplicate certificates per week.
Check `hostops sites get <domain>` for the `cert_file` the vhost actually uses,
compare with the path acme.sh installs to, then propose a reload or a vhost fix.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "acme.sh said Cert success, we're done" | Only `served_matches_disk: true` proves it. |
| "The user said renew it, so I can pass --confirm now" | The user approved the goal, not this plan. Show the plan, get a yes. |
| "89 days left, cert is fine" | Check `staging`. A staging cert is broken at any expiry. |
| "Exit 5, let me just renew again" | Rate limits. Diagnose the reload path first. |
| "hostops refused, I'll run acme.sh directly" | The CLI is the safety boundary. Report the refusal instead. |

See references/diagnosis.md for paths and edge cases.
