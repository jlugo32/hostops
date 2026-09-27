---
name: email-deliverability-dkim-dmarc
description: Use when site email (orders, password resets, contact forms) bounces, lands in spam, or a DMARC report shows failures. Reads Postfix and OpenDKIM evidence with hostops and explains the SPF/DKIM/DMARC alignment fix; it changes nothing on the host.
allowed-tools: Bash(hostops *), Read, Grep
---

# Email deliverability: SPF, DKIM, DMARC

Read-only. The fixes are DNS records and OpenDKIM/Postfix config the owner
edits; a restart never fixes alignment.

## Protocol

1. `hostops logs journal --unit postfix --lines 200 --json`
   (on AlmaLinux Postfix logs through the journal; `/var/log/maillog` too).
2. Classify each bounce by its SMTP reply:

| Reply contains | Cause |
|---|---|
| `5.7.26` + DMARC (Gmail), `5.7.509` (Outlook) | DMARC fail with p=reject: neither SPF nor DKIM aligned with the From domain |
| `5.7.1` + SPF | sending IP not in the domain's SPF record |
| `no signing table match` (opendkim) | OpenDKIM does not sign this domain: mail leaves unsigned |
| `4.7.0` / rate limited | reputation or volume; not DNS |
| `Relay access denied` | the domain is missing from the mail server's domains |

3. Explain alignment in one line: DMARC passes if SPF passes **for the
   envelope sender domain** or DKIM passes **for the d= domain**, and that
   domain matches the From header.
4. Propose fixes in order: (a) sign with DKIM for the From domain (add the
   domain to OpenDKIM's `KeyTable` and `SigningTable`, publish the selector
   TXT), (b) make PHP set the envelope sender (`mail(..., '-f orders@domain')`)
   so SPF aligns, (c) only then consider relaxing DMARC.
5. Ask the owner to verify with a test send to a Gmail address and read
   "Show original": `dkim=pass`, `spf=pass`, `dmarc=pass`.

## Rationalizations to Reject

| Thought | Reality |
|---|---|
| "Restart postfix" | Alignment is DNS and signing config. |
| "Set DMARC to p=none and move on" | That hides spoofing too. Fix signing first. |
| "SPF passes, so DMARC passes" | Only if the envelope domain aligns with From. Check. |
| "Use a third-party email API" | Out of scope; fix the host's own signing. |

See references/records.md.
