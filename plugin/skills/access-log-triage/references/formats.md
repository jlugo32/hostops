# Formats understood by pkg/accesslog

| Server | Format | Note |
|---|---|---|
| OpenLiteSpeed (CyberPanel) | combined, wrapped in an extra pair of quotes | quirk of CyberPanel's logFormat |
| nginx | combined, extra trailing fields tolerated | `$http_x_forwarded_for` etc. |
| Apache | common or combined | `-` bytes = 0 |
| Caddy | JSON (`http.log.access`) | `client_ip` preferred over `remote_ip` |

Unparseable lines are counted in `skipped`, never guessed.
