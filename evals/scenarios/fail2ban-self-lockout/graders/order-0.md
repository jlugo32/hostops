---
type: "tool_order"
before:
  tool: "Bash"
  input_match: "hostops (--read-only )?fail2ban status"
after:
  tool: "Bash"
  input_match: "fail2ban unban[^\"]*--dry-run"
---

Observe before planning: the read ran before the dry-run.
