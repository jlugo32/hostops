# Fix snippets (owner runs these from a console session)

## SSH
```bash
cat >/etc/ssh/sshd_config.d/00-hardening.conf <<'X'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 4
X
sshd -t && systemctl reload sshd
# keep this session open; test key login in a second terminal first
```
`00-` sorts before cloud-init's `50-` file, so it wins.

## Automatic security updates
```bash
dnf install -y dnf-automatic
sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
```

## Secrets file permissions
```bash
chown <siteuser>:<siteuser> /home/<domain>/public_html/config.php
chmod 600 /home/<domain>/public_html/config.php
```
On CyberPanel the site user is the vhost's `extUser`.

## Firewall
Enable firewalld from the provider's console, not over SSH, the first time.
Keep `ssh`, `http`, `https` and CyberPanel's `8090/tcp` (restrict 8090 to
your IP with a rich rule if possible).
