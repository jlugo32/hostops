#!/usr/bin/env bash
# Enforces the plugin's skill contract. Usage: scripts/check-skills.sh [plugin-dir]
set -euo pipefail

plugin="${1:-plugin}"
fail=0
err() { printf 'check-skills: %s\n' "$*" >&2; fail=1; }

# Write commands a skill can reach. Mentioning one in a skill body means the
# skill has write reach and must set disable-model-invocation: true.
write_re='hostops (sites reload|cert renew|service restart|fail2ban (unban|ban)|backup (create|restore))'

count=0
for f in "$plugin"/skills/*/SKILL.md; do
  count=$((count + 1))
  dir=$(basename "$(dirname "$f")")
  front=$(awk 'NR==1 && $0=="---"{on=1; next} on && $0=="---"{exit} on{print}' "$f")
  name=$(printf '%s\n' "$front" | sed -n 's/^name: *//p')
  desc=$(printf '%s\n' "$front" | sed -n 's/^description: *//p')
  tools=$(printf '%s\n' "$front" | sed -n 's/^allowed-tools: *//p')
  dmi=$(printf '%s\n' "$front" | sed -n 's/^disable-model-invocation: *//p')
  lines=$(wc -l <"$f")

  [[ "$name" == "$dir" ]] || err "$f: name '$name' does not match directory '$dir'"
  [[ "$name" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || err "$f: name is not kebab-case"
  (( ${#name} <= 64 )) || err "$f: name longer than 64 characters"
  [[ "$desc" == "Use when "* ]] || err "$f: description must start with the trigger phrase 'Use when'"
  (( lines < 500 )) || err "$f: $lines lines (limit 499); move detail to references/"
  grep -q '^## Rationalizations to Reject' "$f" || err "$f: missing '## Rationalizations to Reject'"

  IFS=',' read -ra parts <<<"$tools"
  [[ ${#parts[@]} -gt 0 && -n "$tools" ]] || err "$f: allowed-tools missing"
  for t in "${parts[@]}"; do
    t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
    case "$t" in
      'Bash(hostops *)'|Read|Grep) ;;
      *) err "$f: allowed-tools may only contain Bash(hostops *), Read, Grep (found '$t')" ;;
    esac
  done

  if grep -Eq "$write_re" "$f"; then
    [[ "$dmi" == "true" ]] || err "$f: reaches a write command but lacks disable-model-invocation: true"
  fi
done

(( count == 10 )) || err "expected 10 skills, found $count"
for a in ops-planner incident-triage hardening-reviewer; do
  [[ -f "$plugin/agents/$a.md" ]] || err "missing agent $a"
done
if find "$plugin/hooks" -type f ! -name README.md | grep -q .; then
  err "hooks/ must stay empty in v0.1 (ADR-0005)"
fi

if (( fail )); then exit 1; fi
echo "check-skills: $count skills OK"
