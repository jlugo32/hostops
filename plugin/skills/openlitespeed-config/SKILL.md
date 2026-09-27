---
name: openlitespeed-config
description: Use when an OpenLiteSpeed vhost change needs checking or applying, a site returns 404/403/500 after a config edit, or someone asks to "restart the web server". Checks vhost syntax with hostops and applies changes only through a graceful, confirmed reload.
allowed-tools: Bash(hostops *), Read, Grep
disable-model-invocation: true
---

# OpenLiteSpeed configuration

OpenLiteSpeed silently ignores directives it does not recognise, and it
ignores `Header`, `<IfModule>` and `Require` lines in `.htaccess` entirely. A
typo therefore does not fail loudly; the site just misbehaves.

## Protocol

1. **Observe**
   ```bash
   hostops sites check --json          # all vhosts
   hostops sites get <domain> --json   # docRoot, aliases, cert, php, listeners
   ```
   `problems` lists unknown directives with line numbers, missing docRoot,
   unmapped listeners and unreadable configs. `sites check` exits 5 when any
   site has a problem.
2. **Fix config by hand, not with hostops.** hostops never edits config. Tell
   the user the exact file and line, e.g. `docRot` → `docRoot` at
   `/usr/local/lsws/conf/vhosts/<domain>/vhost.conf:1`.
3. **Reload** after the fix: `hostops sites reload --dry-run`. It refuses
   (exit 3) while any vhost has a blocking problem. Show the plan, ask, then
   `hostops sites reload --confirm=<token>`.
4. **Verify**: exit 0 means `lsws` is active after the graceful restart. Then
   `hostops sites check <domain>` again.

"Restart the web server" means `sites reload` (graceful: in-flight requests
finish). `hostops service restart lsws` drops every connection on every site;
offer it only if a reload does not recover the server.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "Reload will surface the error" | OLS reloads happily with a typo. Run `sites check` first. |
| "A restart is more thorough" | It cuts every site's in-flight requests. Reload first. |
| "I'll add the header in .htaccess" | OLS ignores it. Use `extraHeaders` in a vhost `context` block. |
| "sites reload refused, I'll call systemctl" | The refusal is the pre-flight doing its job. Fix the config. |
| "The user asked for a restart, so skip the dry-run" | Every write needs the plan shown and a yes. |

See references/ols-gotchas.md.
