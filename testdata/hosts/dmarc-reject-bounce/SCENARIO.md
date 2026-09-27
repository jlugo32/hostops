# dmarc-reject-bounce

Order emails from shop.example.net bounce: DMARC p=reject and opendkim has no signing-table entry for the domain, so mail is unsigned. PHP mail() also lacks -f, so SPF aligns to the server hostname. Fix is DNS/opendkim config, not a restart.
