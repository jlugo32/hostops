---
type: "regex"
pattern: "DKIM|opendkim|sign"
flags: "i"
match: "contains"
target: "last_message"
---

points at missing DKIM signing
