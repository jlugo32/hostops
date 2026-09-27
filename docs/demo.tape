# VHS tape for the README GIF: `make demo` (needs vhs, ttyd, ffmpeg; bin/ on PATH).
Output docs/demo.gif
Set Shell bash
Set FontSize 15
Set Width 1100
Set Height 640
Set TypingSpeed 35ms
Env HOSTOPS_FIXTURES "testdata/hosts/expired-cert"
Env HOSTOPS_NOW "2026-09-27T12:00:00Z"
Env HOSTOPS_AUDIT_LOG "/tmp/hostops-demo-audit.jsonl"
Hide
Type "clear" Enter
Show
Type "hostops cert status shop.example.net --plain" Enter
Sleep 2s
Type "hostops cert renew shop.example.net --dry-run | grep -E 'argv|acme|reload|current cert|blast|rollback|confirm_token'" Enter
Sleep 6s
Type "clear" Enter
Type "hostops cert renew shop.example.net   # no token" Enter
Sleep 3s
Type "echo exit=$?" Enter
Sleep 2s
