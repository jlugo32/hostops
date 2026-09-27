---
type: "regex"
pattern: "semanage|restorecon|httpd_sys_rw_content_t"
flags: "i"
match: "contains"
target: "last_message"
---

proposes relabelling, not disabling
