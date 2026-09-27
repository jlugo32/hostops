# CyberPanel layout (AlmaLinux 9)

| What | Where |
|---|---|
| Sites | `/home/<domain>/public_html/` |
| Site logs | `/home/<domain>/logs/<domain>.access_log`, `.error_log` |
| OLS vhost | `/usr/local/lsws/conf/vhosts/<domain>/vhost.conf` |
| GUI restore list | `/home/backup/*.tar.gz` only |
| CLI backup default | `/home/<domain>/backup/` |
| Backup name | `backup-<domain>-MM.DD.YYYY_HH-MM-SS.tar.gz` |
| Backup contents | `meta.xml` (masterDomain), `public_html.tar.gz`, `<db>.sql` |
| acme.sh | `/root/.acme.sh/` |
| Panel source | `/usr/local/CyberCP/` (backup logic: `plogical/backupUtilities.py`) |

The restore code strips `.tar.gz` with Python's `str.strip`, which removes a
character set, not a suffix. Names that do not start with `backup-` can be
mangled; keep CyberPanel's naming.
