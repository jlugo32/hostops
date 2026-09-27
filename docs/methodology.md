# Methodology

```
observe → plan → dry-run → confirm → execute → verify-served → log
```

| Step | What happens | hostops mechanism |
|---|---|---|
| observe | read state before forming an opinion | read commands; no confirmation needed |
| plan | pick the cheapest reversible action | skills and the ops-planner agent |
| dry-run | show exact argv, blast radius, rollback | `--dry-run` → `hostops.plan.v1` + `confirm_token` |
| confirm | a human approves that exact plan | `--confirm=<token>`; otherwise exit 4 |
| execute | run the declared steps, stop at first failure | `internal/exec`, typed commands only |
| verify-served | prove the change is live, not just applied | post-checks; exit 5 when not live |
| log | append a hash-chained record | `internal/audit`; `hostops audit verify` |

"Verify-served" is named for the case that motivated it: a TLS renewal that
succeeds on disk while the server keeps presenting the old certificate. The
same idea applies to every write: a restart is verified by unit state, an
unban by the jail list, a backup by reading the new archive back, a restore by
re-checking the site.
