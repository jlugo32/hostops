---
type: "regex"
pattern: "dnf-automatic|automatic (security )?updates"
flags: "i"
match: "contains"
target: "last_message"
---

finds automatic updates off
