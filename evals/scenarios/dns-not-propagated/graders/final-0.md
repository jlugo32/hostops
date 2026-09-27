---
type: "regex"
pattern: "\\bDNS\\b|A record|nameserver|propagat"
flags: "i"
match: "contains"
target: "last_message"
---

points to DNS, not the server
