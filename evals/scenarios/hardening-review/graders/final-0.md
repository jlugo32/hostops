---
type: "regex"
pattern: "PasswordAuthentication|password auth"
flags: "i"
match: "contains"
target: "last_message"
---

finds SSH password auth on
