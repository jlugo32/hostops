#!/usr/bin/env bash
# Hardening assertions for deploy/. Runs in the almalinux:9 CI job (systemd
# 252 supports offline analysis) and locally where systemd/visudo exist.
set -euo pipefail
cd "$(dirname "$0")/.."

unit=deploy/hostops.service
fail=0
bad() { echo "assert-hardening: $*" >&2; fail=1; }

for want in 'NoNewPrivileges=yes' 'ProtectSystem=strict' 'PrivateTmp=yes' \
            'SystemCallFilter=@system-service' 'ProtectHome=read-only' 'RestrictSUIDSGID=yes' \
            'MemoryDenyWriteExecute=yes' 'ExecStart=/usr/bin/hostops --read-only'; do
  grep -q "^${want}" "$unit" || bad "$unit lacks ${want}"
done
if grep -Eq '^ExecStart=.*(--confirm|--dry-run)' "$unit"; then bad "sidecar must not run write commands"; fi

if command -v systemd-analyze >/dev/null; then
  if [[ "${CI:-}" == "true" ]]; then
    # CI container only: install for real, as an operator would.
    install -m 0755 bin/hostops /usr/bin/hostops
    install -m 0644 deploy/hostops.service deploy/hostops.timer /etc/systemd/system/
    dir=/etc/systemd/system
  else
    # Anywhere else: analyse a private copy; never touch /etc.
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    sed "s|/usr/bin/hostops|$PWD/bin/hostops|" deploy/hostops.service >"$dir/hostops.service"
    cp deploy/hostops.timer "$dir/"
  fi
  systemd-analyze verify "$dir/hostops.service" "$dir/hostops.timer" || bad "systemd-analyze verify failed"
  score=$(systemd-analyze security --offline=true "$dir/hostops.service" 2>/dev/null | grep 'Overall exposure level' | grep -oE '[0-9]+\.[0-9]+' | head -1)
  echo "assert-hardening: exposure score ${score:-unknown}"
  if [[ -n "${score:-}" ]] && awk -v s="$score" 'BEGIN{exit !(s > 3.0)}'; then bad "exposure $score > 3.0"; fi
else
  echo "assert-hardening: systemd-analyze not available, skipped unit analysis"
fi

if command -v visudo >/dev/null; then
  visudo -cf deploy/sudoers.d/hostops >/dev/null || bad "visudo rejects deploy/sudoers.d/hostops"
else
  echo "assert-hardening: visudo not available, skipped"
fi
# No sudoers wildcard may follow a command that takes a domain or path.
if grep -E '^(Cmnd_Alias|[[:space:]]).*(acme\.sh|certbot|cyberpanel|mysqldump|fail2ban-client (unban|set))[^,]*\*' deploy/sudoers.d/hostops; then
  bad "wildcard argument on a parameterised command"
fi
if grep -Eq 'NOPASSWD: *ALL' deploy/sudoers.d/hostops; then bad "NOPASSWD: ALL"; fi

(( fail == 0 )) && echo "assert-hardening: OK"
exit "$fail"
