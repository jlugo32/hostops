package cli

var (
	fDryRun  = flagSpec{false, "print the plan and a confirm token; change nothing"}
	fConfirm = flagSpec{true, "token printed by --dry-run"}
	writeFl  = map[string]flagSpec{"dry-run": fDryRun, "confirm": fConfirm}
)

func withWrite(extra map[string]flagSpec) map[string]flagSpec {
	m := map[string]flagSpec{}
	for k, v := range writeFl {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

var reg []*Command

// registry returns every command. The order is the help order.
func registry() []*Command {
	if reg != nil {
		return reg
	}
	reg = []*Command{
		{Path: "sites list", Summary: "list hosted sites from the web server config", Run: sitesList},
		{Path: "sites get", Args: "<domain>", Summary: "show one site's config, cert and problems", Run: sitesGet},
		{Path: "sites check", Args: "[domain]", Summary: "check vhost syntax, docroot, listeners, cert files", Run: sitesCheck},
		{Path: "sites reload", Summary: "graceful web server reload (pre-checks all vhosts)", Write: true, Flags: writeFl, Run: sitesReload},

		{Path: "cert status", Args: "[domain]", Summary: "certificate expiry, issuer, staging flag; --served probes the live cert",
			Flags: map[string]flagSpec{"served": {false, "also fetch the cert served on 127.0.0.1:443 (SNI)"}}, Run: certStatus},
		{Path: "cert renew", Args: "<domain>", Summary: "renew via acme.sh/certbot, reload, verify the served cert", Write: true,
			Flags: withWrite(map[string]flagSpec{"verify-served": {false, "verify the served cert after renewal (default on; =false gives exit 6)"}}), Run: certRenew},

		{Path: "service status", Args: "<unit>", Summary: "systemd unit state, restarts, last result", Run: serviceStatus},
		{Path: "service restart", Args: "<unit>", Summary: "restart a unit and verify it is active (sshd/network units refused)", Write: true, Flags: writeFl, Run: serviceRestart},

		{Path: "firewall list", Summary: "active firewalld zones, services, ports, rich rules", Run: firewallList},

		{Path: "fail2ban status", Args: "[jail]", Summary: "jails, failure counts, banned IPs", Run: fail2banStatus},
		{Path: "fail2ban unban", Args: "<ip>", Summary: "unban an IP (all jails unless --jail)", Write: true,
			Flags: withWrite(map[string]flagSpec{"jail": {true, "limit to one jail"}}), Run: fail2banUnban},
		{Path: "fail2ban ban", Args: "<ip>", Summary: "ban an IP in a jail (refuses your own session IP)", Write: true,
			Flags: withWrite(map[string]flagSpec{"jail": {true, "jail to ban in (required)"}}), Run: fail2banBan},

		{Path: "baseline check", Summary: "read-only hardening baseline mapped to NSA/CISA AA23-278A", Run: baselineCheck},

		{Path: "backup list", Args: "[domain]", Summary: "backups with age and GUI visibility", Run: backupList},
		{Path: "backup verify", Args: "<path>", Summary: "read the archive to EOF; --gui-compatible adds CyberPanel restore checks",
			Flags: map[string]flagSpec{"gui-compatible": {false, "require CyberPanel GUI-restore compatibility"}}, Run: backupVerify},
		{Path: "backup create", Args: "<domain>", Summary: "create a backup and verify the new archive", Write: true, Flags: writeFl, Run: backupCreate},
		{Path: "backup restore", Args: "<path>", Summary: "verify, take a safety backup, then restore", Write: true, Flags: writeFl, Run: backupRestore},

		{Path: "db list", Summary: "databases (system schemas hidden unless --all)", Flags: map[string]flagSpec{"all": {false, "include system schemas"}}, Run: dbList},
		{Path: "db size", Summary: "per-schema size, free space and table count", Run: dbSize},
		{Path: "db slowlog", Summary: "slow query log aggregated by statement fingerprint",
			Flags: map[string]flagSpec{"top": {true, "number of fingerprints (default 10)"}}, Run: dbSlowlog},

		{Path: "logs top", Args: "[domain]", Summary: "access-log summary: status, IPs, paths, probes",
			Flags: map[string]flagSpec{"file": {true, "log file under /home or /var/log instead of a site's log"}, "lines": {true, "tail N lines (default 5000)"}, "top": {true, "rows per ranking (default 10)"}}, Run: logsTop},
		{Path: "logs journal", Summary: "systemd journal, newest last",
			Flags: map[string]flagSpec{"unit": {true, "unit to filter"}, "lines": {true, "N entries (default 100)"}, "priority": {true, "max priority: emerg..debug or 0-7"}}, Run: logsJournal},

		{Path: "audit verify", Summary: "recompute the audit log hash chain", Run: auditVerify},
	}
	return reg
}
