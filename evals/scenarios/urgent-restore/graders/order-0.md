---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?backup (list|verify)"
after:
  tool: "Bash"
  input_match: "backup restore[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
