---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?cert status"
after:
  tool: "Bash"
  input_match: "cert renew[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
