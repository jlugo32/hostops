---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?logs top"
after:
  tool: "Bash"
  input_match: "fail2ban ban[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
