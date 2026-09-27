---
name: vps-hardening-almalinux
description: Use when asked whether an AlmaLinux/RHEL 9 web server is hardened, secure or compliant, or before exposing a new VPS. Runs the read-only hostops baseline, explains each finding against NSA/CISA AA23-278A, and proposes fixes for the owner to apply.
allowed-tools: Bash(hostops *), Read, Grep
---

# AlmaLinux 9 hardening review (read-only)

This skill never changes the host. hostops has no write command for SSH,
firewall or SELinux configuration in v0.1, on purpose: a wrong change there
locks the owner out. You observe, explain and propose.

## Protocol

1. `hostops baseline check --json` (exits 5 when any check fails; that is a
   result, not an error).
2. `hostops firewall list --json` and `hostops fail2ban status --json` for
   context.
3. For each `fail`, then each `warn`: state the evidence, why it matters
   (the `control` field), and the `proposed_fix`. Order by blast radius:
   remote access first.
4. Give the fix as commands for the owner to run from a console session,
   never from the only SSH session, with a way to test before closing it.

## Checks and why

| ID | Check | Why |
|---|---|---|
| HO-SSH-01 | root login restricted | AA23-278A #2 privilege separation |
| HO-SSH-02 | password auth off | #7/#9 credential attacks |
| HO-SSH-03 | MaxAuthTries <= 4 | #9 brute force |
| HO-FW-01 | firewalld running | #4 segmentation |
| HO-F2B-01 | fail2ban active | #3 monitoring and response |
| HO-SEL-01 | SELinux enforcing | #10 unrestricted code execution |
| HO-UPD-01 | dnf-automatic enabled | #5 patch management |
| HO-PERM-01 | config.php/.env not world-readable | #8/#9 exposed secrets |

**sshd drop-ins win.** sshd uses the first value it reads, and
`Include /etc/ssh/sshd_config.d/*.conf` comes first. A cloud-init file there
with `PasswordAuthentication yes` overrides `no` in the main file. hostops
reads files in the same order.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "sshd_config says no, so passwords are off" | Check drop-ins; HO-SSH-02 already did. |
| "Just setenforce 0 to stop the denials" | That removes a control. Fix labels (see systemd-cron-runbooks). |
| "I'll apply the fix, it's one line" | This skill is read-only. Propose; the owner applies from a console. |
| "Fail2ban is on, SSH is safe" | It only slows guessing. Disable passwords. |

See references/fixes.md for tested fix snippets.
