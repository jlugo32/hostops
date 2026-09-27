# OOM and SELinux notes

## lsphp OOM on OpenLiteSpeed
Worst-case PHP memory ≈ LSAPI_CHILDREN × memHardLimit per vhost. Ten children
at 1 GB each on an 8 GB host that also runs MariaDB will be killed under load.
Start with `LSAPI_CHILDREN=4`, `memHardLimit 512M`, measure, adjust.

## SELinux on CyberPanel hosts
CyberPanel ships Permissive. On Enforcing hosts, writable web dirs need
`httpd_sys_rw_content_t`:
```bash
semanage fcontext -a -t httpd_sys_rw_content_t '/home/example.com/public_html/uploads(/.*)?'
restorecon -Rv /home/example.com/public_html/uploads
```
`audit2why < /var/log/audit/audit.log` explains a denial before you change anything.
