package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/adapters/certs"
	"github.com/jlugo32/hostops/internal/adapters/fail2ban"
	"github.com/jlugo32/hostops/internal/adapters/systemd"
	"github.com/jlugo32/hostops/internal/confirm"
	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/hosterr"
	"github.com/jlugo32/hostops/internal/validate"
)

func (c *Ctx) newPlan(target string, steps []exec.Command) confirm.Plan {
	p := confirm.NewPlan(c.Cmd.Path, target, c.Cfg.Adapter)
	if c.Cfg.Fixtures != "" {
		p.Host = "fixture-host" // stable goldens; real hosts bind tokens to their hostname
	}
	for _, s := range steps {
		p.Steps = append(p.Steps, confirm.Step{ID: s.ID, Argv: s.Argv(), Mutates: s.Mutates})
	}
	return p
}

// execute runs steps in order and stops at the first failure.
func (c *Ctx) execute(steps []exec.Command, res *WriteResult) error {
	for _, s := range steps {
		r, err := c.Env.Exec(c, s)
		sr := StepResult{ID: s.ID, Argv: s.Argv(), ExitCode: r.ExitCode}
		if err != nil {
			sr.ExitCode = -1
			sr.Error = validate.Printable(err.Error())
			res.Steps = append(res.Steps, sr)
			return err
		}
		if r.ExitCode != 0 {
			sr.Error = validate.Printable(strings.TrimSpace(string(r.Stderr)))
			res.Steps = append(res.Steps, sr)
			return hosterr.New(hosterr.General, "step %s exited %d", s.ID, r.ExitCode)
		}
		res.Steps = append(res.Steps, sr)
	}
	return nil
}

func newResult(c *Ctx, target string) *WriteResult {
	return &WriteResult{Schema: "hostops.result.v1", Command: c.Cmd.Path, Target: target, Steps: []StepResult{}, Verification: []VerifyItem{}}
}

// finish sets OK and maps failed verification to exit 5.
func (r *WriteResult) finish() (any, error) {
	r.OK = true
	var bad []string
	for _, v := range r.Verification {
		if !v.OK {
			r.OK = false
			bad = append(bad, v.Check)
		}
	}
	if !r.OK {
		return r, hosterr.New(hosterr.Verification, "change applied but verification failed: %s", strings.Join(bad, ", "))
	}
	return r, nil
}

func (c *Ctx) isActive(unit string) (bool, string) {
	r, err := c.Env.Exec(c, exec.Command{ID: "systemd.is-active", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("is-active"), exec.Param(unit)}})
	if err != nil {
		return false, err.Error()
	}
	s := strings.TrimSpace(string(r.Stdout))
	return s == "active", s
}

func blocking(s adapters.Site) []string {
	var out []string
	for _, p := range s.Problems {
		if strings.Contains(p, "syntax") || strings.Contains(p, "unknown directive") || strings.Contains(p, "no docRoot") || strings.Contains(p, "unreadable") {
			out = append(out, s.Domain+": "+p)
		}
	}
	return out
}

func sitesReload(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	sites, err := c.sites()
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, s := range sites {
		bad = append(bad, blocking(s)...)
	}
	if len(bad) > 0 {
		return nil, hosterr.New(hosterr.Validation, "pre-flight failed, not reloading: %s", strings.Join(bad, "; "))
	}
	steps := c.Web.ReloadSteps()
	p := c.newPlan(c.Web.Unit(), steps)
	p.Diff = []string{fmt.Sprintf("graceful reload of %s; %d vhosts passed pre-flight", c.Web.Unit(), len(sites))}
	p.BlastRadius = fmt.Sprintf("every site on this host (%d); graceful, in-flight requests finish, but a bad config affects all of them", len(sites))
	p.Rollback = "revert the config edit that prompted the reload, then reload again"
	p.Verify = c.Web.Unit() + " is active after the reload"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, c.Web.Unit())
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	ok, st := c.isActive(c.Web.Unit())
	res.Verification = append(res.Verification, VerifyItem{"unit_active", ok, c.Web.Unit() + ": " + st})
	return res.finish()
}

func certRenew(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	d, err := validate.Domain(c.Pos[0])
	if err != nil {
		return nil, err
	}
	vhostCert := ""
	if s, err := c.site(d); err == nil {
		vhostCert = s.CertFile
	}
	is, ok := certs.FindIssuer(c.Env, d)
	if !ok {
		return nil, hosterr.New(hosterr.Validation, "no acme.sh or certbot renewal config for %s; issue it first (CyberPanel: SSL > Manage SSL)", d)
	}
	before, _, berr := certs.OnDisk(c.Env, d, vhostCert)
	steps := append([]exec.Command{certs.RenewCmd(is, d)}, c.Web.ReloadSteps()...)
	p := c.newPlan(d, steps)
	if berr == nil {
		p.Diff = append(p.Diff, fmt.Sprintf("current cert: expires %s (%d days), issuer %s", before.NotAfter[:10], before.DaysLeft, before.Issuer))
		if before.Staging {
			p.Diff = append(p.Diff, "current cert is from a STAGING issuer (browsers reject it)")
		}
	} else {
		p.Diff = append(p.Diff, "no current cert on disk")
	}
	p.Diff = append(p.Diff, "new: 90-day cert from Let's Encrypt production via "+is.Client)
	if is.StagingConfigured {
		p.Diff = append(p.Diff, "saved renewal config points at STAGING; this plan forces the production server")
	}
	p.BlastRadius = fmt.Sprintf("TLS for %s; the %s reload touches every site gracefully. Let's Encrypt allows 5 duplicate certs per week", d, c.Web.Unit())
	p.Rollback = "the previous cert stays in the ACME client's backup; reinstall it and reload if the new one misbehaves"
	p.Verify = "served cert (127.0.0.1:443, SNI) equals the new on-disk cert, is not staging, and has >= 30 days left"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, d)
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	after, _, aerr := certs.OnDisk(c.Env, d, vhostCert)
	if aerr != nil {
		res.Verification = append(res.Verification, VerifyItem{"disk_cert_present", false, "no cert on disk after renewal"})
		return res.finish()
	}
	renewed := berr != nil || after.Fingerprint != before.Fingerprint
	res.Verification = append(res.Verification,
		VerifyItem{"disk_cert_renewed", renewed && after.DaysLeft >= 30, fmt.Sprintf("on-disk cert expires %s (%d days)", after.NotAfter[:10], after.DaysLeft)},
		VerifyItem{"not_staging", !after.Staging, "issuer " + after.Issuer})
	if c.Flags["verify-served"] == "false" {
		res.Note = "served-cert verification skipped (--verify-served=false); result is inconclusive"
		if r, err := res.finish(); err != nil {
			return r, err
		}
		return res, hosterr.New(hosterr.Partial, "renewed on disk; served cert not verified")
	}
	sc, perr := c.Env.Probe.ServedCert(c, d)
	if perr != nil {
		res.Verification = append(res.Verification, VerifyItem{"served_matches_disk", false, "could not fetch served cert: " + validate.Printable(perr.Error())})
		return res.finish()
	}
	si := certs.Describe(d, "served", "", sc, c.Env.Now())
	res.Verification = append(res.Verification, VerifyItem{"served_matches_disk", si.Fingerprint == after.Fingerprint,
		fmt.Sprintf("served cert expires %s (%d days), sha256 %s…", si.NotAfter[:10], si.DaysLeft, si.Fingerprint[:12])})
	return res.finish()
}

func serviceRestart(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	u, err := validate.Unit(c.Pos[0])
	if err != nil {
		return nil, err
	}
	if systemd.IsProtected(u) {
		return nil, hosterr.New(hosterr.Permission, "refusing to restart %s: it can cut your own access; do it from a console session", u)
	}
	out, err := c.run(systemd.StatusCmd(u))
	if err != nil {
		return nil, err
	}
	st, err := systemd.ParseShow(u, out)
	if err != nil {
		return nil, err
	}
	if st.Load != "loaded" {
		return nil, hosterr.New(hosterr.Validation, "unit %s is %s", u, st.Load)
	}
	steps := []exec.Command{systemd.RestartCmd(u)}
	p := c.newPlan(u, steps)
	p.Diff = []string{fmt.Sprintf("%s: %s/%s (result %s, %d restarts) → restarted", st.Unit, st.Active, st.Sub, st.Result, st.Restarts)}
	p.BlastRadius = "clients of " + st.Unit + " see a short outage"
	if strings.HasPrefix(systemd.Normalize(u), "lsws") || systemd.Normalize(u) == "nginx" {
		p.BlastRadius = "every site on this host drops in-flight requests; prefer `hostops sites reload`"
	}
	if strings.Contains(systemd.Normalize(u), "mariadb") || strings.Contains(systemd.Normalize(u), "mysql") {
		p.BlastRadius = "every site using the database errors until it is back; InnoDB may run crash recovery"
	}
	p.Rollback = "none for a restart; if it fails to start, read `hostops logs journal --unit " + u + "`"
	p.Verify = st.Unit + " is loaded and active afterwards"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, u)
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	out, err = c.run(systemd.StatusCmd(u))
	after, perr := systemd.ParseShow(u, out)
	if err != nil || perr != nil {
		res.Verification = append(res.Verification, VerifyItem{"unit_active", false, "could not read status after restart"})
		return res.finish()
	}
	res.Verification = append(res.Verification, VerifyItem{"unit_active", after.Healthy, fmt.Sprintf("%s/%s result=%s", after.Active, after.Sub, after.Result)})
	return res.finish()
}

func (c *Ctx) jailStatus(jail string) (fail2ban.Jail, error) {
	out, err := c.run(fail2ban.JailCmd(jail))
	if err != nil {
		return fail2ban.Jail{}, err
	}
	return fail2ban.ParseJail(jail, out), nil
}

func (c *Ctx) jails(only string) ([]fail2ban.Jail, error) {
	names := []string{only}
	if only == "" {
		out, err := c.run(fail2ban.StatusCmd())
		if err != nil {
			return nil, err
		}
		names = fail2ban.ParseJails(out)
	}
	var js []fail2ban.Jail
	for _, n := range names {
		if _, err := validate.Ident("jail", n); err != nil {
			continue
		}
		j, err := c.jailStatus(n)
		if err != nil {
			return nil, err
		}
		js = append(js, j)
	}
	return js, nil
}

func bannedIn(js []fail2ban.Jail, ip string) []string {
	var out []string
	for _, j := range js {
		for _, b := range j.BannedIPs {
			if b == ip {
				out = append(out, j.Name)
			}
		}
	}
	return out
}

func (c *Ctx) jailFlag(required bool) (string, error) {
	j, ok := c.Flags["jail"]
	if !ok {
		if required {
			return "", hosterr.New(hosterr.Validation, "--jail is required")
		}
		return "", nil
	}
	return validate.Ident("jail", j)
}

func fail2banUnban(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	ip, err := validate.IP(c.Pos[0])
	if err != nil {
		return nil, err
	}
	jail, err := c.jailFlag(false)
	if err != nil {
		return nil, err
	}
	js, err := c.jails(jail)
	if err != nil {
		return nil, err
	}
	in := bannedIn(js, ip.String())
	if len(in) == 0 {
		res := newResult(c, ip.String())
		res.Note = "not banned in any checked jail; nothing to do"
		res.OK = true
		return res, nil
	}
	steps := []exec.Command{fail2ban.UnbanCmd(jail, ip.String())}
	p := c.newPlan(ip.String(), steps)
	p.Diff = []string{"remove " + ip.String() + " from jail(s): " + strings.Join(in, ", ")}
	p.BlastRadius = "one address regains access; if it is an attacker, fail2ban re-bans it after new failures"
	p.Rollback = fmt.Sprintf("hostops fail2ban ban %s --jail %s", ip, in[0])
	p.Verify = "address no longer listed in any jail"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, ip.String())
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	after, err := c.jails(jail)
	if err != nil {
		return res, err
	}
	still := bannedIn(after, ip.String())
	res.Verification = append(res.Verification, VerifyItem{"unbanned", len(still) == 0, "still banned in: " + strings.Join(still, ", ")})
	if len(still) == 0 {
		res.Verification[len(res.Verification)-1].Detail = "not listed in any jail"
	}
	return res.finish()
}

func fail2banBan(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	ip, err := validate.IP(c.Pos[0])
	if err != nil {
		return nil, err
	}
	jail, err := c.jailFlag(true)
	if err != nil {
		return nil, err
	}
	if why := fail2ban.SelfLockout(ip, c.Cfg.ProtectedIPs); why != "" {
		return nil, hosterr.New(hosterr.Validation, "refusing to ban %s: %s", ip, why)
	}
	if _, err := c.jailStatus(jail); err != nil {
		return nil, err
	}
	steps := []exec.Command{fail2ban.BanCmd(jail, ip.String())}
	p := c.newPlan(ip.String(), steps)
	p.Diff = []string{"add " + ip.String() + " to jail " + jail}
	p.BlastRadius = "all traffic the jail's action blocks from " + ip.String() + " (usually every port for sshd-style actions)"
	p.Rollback = "hostops fail2ban unban " + ip.String() + " --jail " + jail
	p.Verify = "address listed in the jail"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, ip.String())
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	j, err := c.jailStatus(jail)
	if err != nil {
		return res, err
	}
	res.Verification = append(res.Verification, VerifyItem{"banned", len(bannedIn([]fail2ban.Jail{j}, ip.String())) == 1, "jail " + jail})
	return res.finish()
}

func (c *Ctx) guiMode() bool { return c.Panel.Name() == "cyberpanel" }

func backupCreate(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	s, err := c.site(c.Pos[0])
	if err != nil {
		return nil, err
	}
	before, _ := backups.List(c.Env, c.Cfg.BackupDir)
	known := map[string]bool{}
	for _, b := range before {
		known[b.Path] = true
	}
	steps := c.Panel.BackupCreateSteps(s.Domain)
	p := c.newPlan(s.Domain, steps)
	p.Diff = []string{"new archive of " + s.Domain + " in " + strings.Join(c.Panel.BackupDirs(s.Domain)[:1], "")}
	if g, ok := c.Panel.(*backups.Generic); ok {
		p.Diff = []string{"new archive " + g.Target(s.Domain)}
	}
	p.BlastRadius = "read load on disk and database while the archive is written; needs free space roughly equal to the site"
	p.Rollback = "delete the new archive if unwanted"
	p.Verify = "a new archive for the domain exists and reads to EOF"
	if c.guiMode() {
		p.Verify += " and passes --gui-compatible"
	}
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, s.Domain)
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	after, _ := backups.List(c.Env, c.Cfg.BackupDir)
	var fresh *backups.Backup
	for i, b := range after {
		if b.Domain == s.Domain && !known[b.Path] {
			fresh = &after[i]
			break
		}
	}
	if fresh == nil {
		res.Verification = append(res.Verification, VerifyItem{"new_archive", false, "no new archive appeared (the CyberPanel CLI exits 0 even on failure)"})
		return res.finish()
	}
	res.Verification = append(res.Verification, VerifyItem{"new_archive", true, fresh.Path})
	rep, err := backups.Verify(c.Env, fresh.Path, c.guiMode())
	if err != nil {
		res.Verification = append(res.Verification, VerifyItem{"archive_valid", false, err.Error()})
		return res.finish()
	}
	res.Verification = append(res.Verification, VerifyItem{"archive_valid", rep.OK, failedOrOK(rep.Checks)})
	return res.finish()
}

func failedOrOK(cs []backups.Check) string {
	if f := failed(cs); f != "" {
		return "failed: " + f
	}
	return "all checks passed"
}

func backupRestore(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	path, err := c.backupPath(c.Pos[0])
	if err != nil {
		return nil, err
	}
	rep, err := backups.Verify(c.Env, path, c.guiMode())
	if err != nil {
		return nil, hosterr.New(hosterr.Validation, "cannot read backup %s", path)
	}
	if !rep.OK {
		return rep, hosterr.New(hosterr.Validation, "refusing to restore: backup failed verification (%s)", failed(rep.Checks))
	}
	dom := backups.DomainFromName(filepath.Base(path))
	s, err := c.site(dom)
	if err != nil {
		return nil, hosterr.New(hosterr.Validation, "backup is for %q, which is not a site on this host", dom)
	}
	steps := append(c.Panel.BackupCreateSteps(s.Domain), c.Panel.BackupRestoreSteps(path)...)
	p := c.newPlan(s.Domain, steps)
	p.Diff = []string{"1. safety backup of the current " + s.Domain, "2. restore files and databases from " + path}
	p.BlastRadius = "overwrites " + s.Domain + " files and databases; the site may error while the restore runs"
	p.Rollback = "restore the safety backup from step 1 (see `hostops backup list " + s.Domain + "`)"
	p.Verify = "site passes `hostops sites check " + s.Domain + "` afterwards"
	if out, err := c.gate(p); out != nil || err != nil {
		return out, err
	}
	res := newResult(c, s.Domain)
	if err := c.execute(steps, res); err != nil {
		return res, err
	}
	after, err := c.site(s.Domain)
	if err != nil {
		res.Verification = append(res.Verification, VerifyItem{"site_healthy", false, err.Error()})
		return res.finish()
	}
	res.Verification = append(res.Verification, VerifyItem{"site_healthy", len(after.Problems) == 0, strings.Join(append([]string{"problems:"}, after.Problems...), " ")})
	if len(after.Problems) == 0 {
		res.Verification[0].Detail = "no problems"
	}
	return res.finish()
}
