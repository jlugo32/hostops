# OpenLiteSpeed gotchas (CyberPanel hosts)

- Config: `/usr/local/lsws/conf/httpd_config.conf` (listeners, vhost
  registration) and `/usr/local/lsws/conf/vhosts/<domain>/vhost.conf`.
- `.htaccess`: only mod_rewrite rules work. `Header`, `<Files>`, `Require`,
  `<IfModule>` are ignored. Deny rules need `RewriteRule ... [F,L]`.
- OLS caches `.htaccess`; a changed deny rule may need a reload to apply.
- Security headers belong in the vhost:
  ```
  context / {
    location $DOC_ROOT/
    allowBrowse 1
    extraHeaders <<<END_extraHeaders
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  END_extraHeaders
  }
  ```
- A site not listed under `listener SSL { map ... }` falls back to the default
  vhost and its certificate.
- `systemctl reload lsws` performs `lswsctrl restart`, a graceful restart.
- PHP per vhost: `extprocessor` → `path /usr/local/lsws/lsphp85/bin/lsphp`,
  `LSAPI_CHILDREN`, `memSoftLimit`, `memHardLimit`.
- Access log format on CyberPanel wraps each line in an extra pair of quotes;
  `hostops logs top` handles it.
