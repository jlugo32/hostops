# Certificate diagnosis reference

## Where certificates live (CyberPanel + OpenLiteSpeed)

- acme.sh state: `/root/.acme.sh/<domain>_ecc/` (ECC) or `/root/.acme.sh/<domain>/`
- installed copy the vhost reads: `/etc/letsencrypt/live/<domain>/fullchain.pem`
- vhost reference: `vhssl { certFile ... }` in `/usr/local/lsws/conf/vhosts/<domain>/vhost.conf`

`hostops cert status` checks, in order: the vhost's certFile, the LE live
path, then acme.sh's directories.

## Staging certificates

Issuer organisation `(STAGING) Let's Encrypt`, CN like `(STAGING) Ersatz
Edamame E1`. They come from testing with `--staging` or a saved `Le_API`
pointing at `acme-staging-v02`. `hostops cert renew` always passes
`--server letsencrypt` so a stale staging config cannot win.

## When the certificate is not the problem

- `cert status --served` shows a valid, matching cert but users see another:
  DNS still points elsewhere, or a CDN terminates TLS. Check with the user
  (`dig +short A <domain>` from their machine) rather than changing the server.
- Wrong cert for a subdomain: the listener has no `map` for it and falls back
  to the default vhost. `hostops sites check <domain>` reports "not mapped".

## Rate limits (Let's Encrypt production)

5 duplicate certificates per exact name set per week; 50 per registered domain
per week. Failed validations: 5 per hour per account per hostname.
