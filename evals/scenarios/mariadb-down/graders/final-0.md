---
type: "regex"
pattern: "No space left|disk (is )?full|errno 28|out of (disk )?space"
flags: "i"
match: "contains"
target: "last_message"
---

finds the full disk
