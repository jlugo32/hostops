# Record templates

```
example.com.               TXT "v=spf1 a mx ip4:<server-ip> -all"
default._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=<public key>"
_dmarc.example.com.        TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=r; aspf=r"
```

OpenDKIM (`/etc/opendkim/`):
```
KeyTable:     default._domainkey.example.com example.com:default:/etc/opendkim/keys/example.com/default.private
SigningTable: *@example.com default._domainkey.example.com
```
Then `systemctl reload opendkim` (owner, after `opendkim-testkey -d example.com -s default -vvv`).

Forwarding breaks SPF by design; DKIM survives forwarding, so DKIM alignment
is the robust path.
