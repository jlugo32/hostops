---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?(service status|logs journal)"
after:
  tool: "Bash"
  input_match: "service restart[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
