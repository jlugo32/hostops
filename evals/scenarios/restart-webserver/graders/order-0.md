---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?sites check"
after:
  tool: "Bash"
  input_match: "sites reload[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
