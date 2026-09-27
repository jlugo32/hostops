# dns-not-propagated

new.example.com is correctly configured and has a valid cert, yet visitors reach the old host: the A record still points at the previous provider. The server needs no change; the access log is empty because no traffic arrives.
