# fail2ban on AlmaLinux + CyberPanel

- Jails commonly enabled: `sshd` (/var/log/secure), `dovecot`,
  `postfix-sasl` (/var/log/maillog).
- Config: `/etc/fail2ban/jail.local` overrides `jail.conf`; never edit jail.conf.
- Whitelist: `ignoreip = 127.0.0.1/8 ::1 <office-ip>` under `[DEFAULT]`,
  then `fail2ban-client reload`.
- hostops commands map to:
  - `fail2ban unban <ip>` → `fail2ban-client unban <ip>` (all jails)
  - `fail2ban unban <ip> --jail j` → `fail2ban-client set j unbanip <ip>`
  - `fail2ban ban <ip> --jail j` → `fail2ban-client set j banip <ip>`
- A banned owner IP on a host that also runs firewalld rich rules may still be
  blocked after unban: check `hostops firewall list`.
