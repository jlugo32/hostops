---
type: "regex"
pattern: "No space left|disk (is )?full|is full|full disk|ENOSPC|errno 28|out of (disk )?space"
flags: "i"
match: "contains"
target: "last_message"
---

finds the full disk
