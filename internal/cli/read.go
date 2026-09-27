package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/adapters/certs"
	"github.com/jlugo32/hostops/internal/adapters/fail2ban"
	"github.com/jlugo32/hostops/internal/adapters/firewalld"
	"github.com/jlugo32/hostops/internal/adapters/logs"
	"github.com/jlugo32/hostops/internal/adapters/mariadb"
	"github.com/jlugo32/hostops/internal/adapters/systemd"
	"github.com/jlugo32/hostops/internal/audit"
	"github.com/jlugo32/hostops/internal/baseline"
	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/hosterr"
	"github.com/jlugo32/hostops/internal/validate"
)

func (c *Ctx) sites() ([]adapters.Site, error) {
	s, err := c.Web.Sites(c)
	if err != nil {
		return nil, hosterr.Wrap(hosterr.General, err, "reading "+c.Web.Name()+" config")
	}
	return s, nil
}

func (c *Ctx) site(domain string) (adapters.Site, error) {
	d, err := validate.Domain(domain)
	if err != nil {
		return adapters.Site{}, err
	}
	all, err := c.sites()
	if err != nil {
		return adapters.Site{}, err
	}
	for _, s := range all {
		if s.Domain == d {
			return s, nil
		}
		for _, a := range s.Aliases {
			if a == d {
				return s, nil
			}
		}
	}
	return adapters.Site{}, hosterr.New(hosterr.Validation, "no site %q in %s config", d, c.Web.Name())
}

// run executes a read command and maps "not installed"/failures to errors.
func (c *Ctx) run(cmd exec.Command) ([]byte, error) {
	r, err := c.Env.Exec(c, cmd)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		msg := strings.TrimSpace(string(r.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(r.Stdout))
		}
		return r.Stdout, hosterr.New(hosterr.General, "%s exited %d: %s", cmd.ID, r.ExitCode, validate.Printable(msg))
	}
	return r.Stdout, nil
}

func sitesList(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	s, err := c.sites()
	if err != nil {
		return nil, err
	}
	return SitesList{Schema: "hostops.sites.v1", Adapter: c.Web.Name(), Sites: nonNil(s)}, nil
}

func sitesGet(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	s, err := c.site(c.Pos[0])
	if err != nil {
		return nil, err
	}
	out := SiteGet{Schema: "hostops.site.v1", Site: s}
	if info, _, err := certs.OnDisk(c.Env, s.Domain, s.CertFile); err == nil {
		out.Cert = &info
	}
	return out, nil
}

func sitesCheck(c *Ctx) (any, error) {
	if len(c.Pos) > 1 {
		return nil, c.positional(1)
	}
	var list []adapters.Site
	if len(c.Pos) == 1 {
		s, err := c.site(c.Pos[0])
		if err != nil {
			return nil, err
		}
		list = []adapters.Site{s}
	} else {
		all, err := c.sites()
		if err != nil {
			return nil, err
		}
		list = all
	}
	r := SitesCheck{Schema: "hostops.sites-check.v1", OK: true, Sites: []SiteCheck{}}
	for _, s := range list {
		sc := SiteCheck{Domain: s.Domain, Problems: append([]string{}, s.Problems...)}
		if info, _, err := certs.OnDisk(c.Env, s.Domain, s.CertFile); err == nil {
			d := info.DaysLeft
			sc.CertDaysLeft = &d
			if info.Staging {
				sc.Problems = append(sc.Problems, "certificate is from a STAGING issuer: "+info.Issuer)
			}
			if d < 0 {
				sc.Problems = append(sc.Problems, fmt.Sprintf("certificate expired %d days ago", -d))
			} else if d < 14 {
				sc.Problems = append(sc.Problems, fmt.Sprintf("certificate expires in %d days", d))
			}
			if !info.CoversName {
				sc.Problems = append(sc.Problems, "certificate does not cover "+s.Domain)
			}
		}
		sc.OK = len(sc.Problems) == 0
		r.OK = r.OK && sc.OK
		r.Sites = append(r.Sites, sc)
	}
	if !r.OK {
		return r, hosterr.New(hosterr.Verification, "one or more sites have problems")
	}
	return r, nil
}

func certStatus(c *Ctx) (any, error) {
	if len(c.Pos) > 1 {
		return nil, c.positional(1)
	}
	var list []adapters.Site
	if len(c.Pos) == 1 {
		s, err := c.site(c.Pos[0])
		if err != nil {
			// A domain may have a cert without a vhost (e.g. mail.*).
			d, verr := validate.Domain(c.Pos[0])
			if verr != nil {
				return nil, verr
			}
			s = adapters.Site{Domain: d}
		}
		list = []adapters.Site{s}
	} else {
		all, err := c.sites()
		if err != nil {
			return nil, err
		}
		list = all
	}
	r := CertStatus{Schema: "hostops.cert-status.v1", Certs: []CertEntry{}}
	for _, s := range list {
		e := CertEntry{Domain: s.Domain}
		if info, _, err := certs.OnDisk(c.Env, s.Domain, s.CertFile); err == nil {
			e.Disk = &info
		} else {
			e.Error = "no certificate on disk"
		}
		if c.Has("served") {
			sc, err := c.Env.Probe.ServedCert(c, s.Domain)
			if err != nil {
				e.ServedError = validate.Printable(err.Error())
			} else {
				si := certs.Describe(s.Domain, "served", "", sc, c.Env.Now())
				e.Served = &si
				m := e.Disk != nil && e.Disk.Fingerprint == si.Fingerprint
				e.ServedMatchesDisk = &m
			}
		}
		r.Certs = append(r.Certs, e)
	}
	return r, nil
}

func serviceStatus(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	u, err := validate.Unit(c.Pos[0])
	if err != nil {
		return nil, err
	}
	out, err := c.run(systemd.StatusCmd(u))
	if err != nil {
		return nil, err
	}
	st, err := systemd.ParseShow(u, out)
	if err != nil {
		return nil, err
	}
	if st.Load == "not-found" {
		return nil, hosterr.New(hosterr.Validation, "unit %q not found", u)
	}
	return ServiceStatus{Schema: "hostops.service-status.v1", Status: st}, nil
}

func firewallList(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	r, err := c.Env.Exec(c, firewalld.StateCmd())
	if err != nil {
		return nil, err
	}
	fw := Firewall{Schema: "hostops.firewall.v1", Running: strings.TrimSpace(string(r.Stdout)) == "running", Zones: []firewalld.Zone{}}
	if !fw.Running {
		return fw, nil
	}
	out, err := c.run(firewalld.ListCmd())
	if err != nil {
		return nil, err
	}
	fw.Zones = firewalld.ParseZones(out)
	return fw, nil
}

func fail2banStatus(c *Ctx) (any, error) {
	if len(c.Pos) > 1 {
		return nil, c.positional(1)
	}
	var jails []string
	if len(c.Pos) == 1 {
		j, err := validate.Ident("jail", c.Pos[0])
		if err != nil {
			return nil, err
		}
		jails = []string{j}
	} else {
		out, err := c.run(fail2ban.StatusCmd())
		if err != nil {
			return nil, err
		}
		jails = fail2ban.ParseJails(out)
	}
	r := Fail2ban{Schema: "hostops.fail2ban.v1", Jails: []fail2ban.Jail{}}
	for _, j := range jails {
		if _, err := validate.Ident("jail", j); err != nil {
			continue // never feed unexpected output back into argv
		}
		out, err := c.run(fail2ban.JailCmd(j))
		if err != nil {
			return nil, err
		}
		r.Jails = append(r.Jails, fail2ban.ParseJail(j, out))
	}
	if ip, ok := fail2ban.SessionIP(); ok {
		r.SessionIP = ip.String()
		for _, j := range r.Jails {
			for _, b := range j.BannedIPs {
				if b == r.SessionIP {
					r.SessionIPBannedIn = append(r.SessionIPBannedIn, j.Name)
				}
			}
		}
	}
	return r, nil
}

func baselineCheck(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	var roots []string
	if s, err := c.sites(); err == nil {
		for _, x := range s {
			if x.DocRoot != "" {
				roots = append(roots, x.DocRoot)
			}
		}
	}
	rep := baseline.Run(c, c.Env, roots)
	if rep.Summary[baseline.Fail] > 0 {
		return rep, hosterr.New(hosterr.Verification, "%d baseline check(s) failed", rep.Summary[baseline.Fail])
	}
	return rep, nil
}

func backupList(c *Ctx) (any, error) {
	if len(c.Pos) > 1 {
		return nil, c.positional(1)
	}
	dom := ""
	if len(c.Pos) == 1 {
		d, err := validate.Domain(c.Pos[0])
		if err != nil {
			return nil, err
		}
		dom = d
	}
	all, err := backups.List(c.Env, c.Cfg.BackupDir)
	if err != nil {
		return nil, err
	}
	r := BackupList{Schema: "hostops.backups.v1", Backups: []backups.Backup{}}
	for _, b := range all {
		if dom == "" || b.Domain == dom {
			r.Backups = append(r.Backups, b)
		}
	}
	return r, nil
}

func (c *Ctx) backupPath(p string) (string, error) {
	return validate.PathUnder(p, backups.GUIDir, c.Cfg.HomeRoot, c.Cfg.BackupDir)
}

func backupVerify(c *Ctx) (any, error) {
	if err := c.positional(1); err != nil {
		return nil, err
	}
	p, err := c.backupPath(c.Pos[0])
	if err != nil {
		return nil, err
	}
	rep, err := backups.Verify(c.Env, p, c.Has("gui-compatible"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, hosterr.New(hosterr.Validation, "no such backup: %s", p)
	}
	if err != nil {
		return nil, hosterr.Wrap(hosterr.General, err, "reading backup")
	}
	if !rep.OK {
		return rep, hosterr.New(hosterr.Verification, "backup failed verification: %s", failed(rep.Checks))
	}
	return rep, nil
}

func failed(cs []backups.Check) string {
	var ids []string
	for _, c := range cs {
		if !c.OK {
			ids = append(ids, c.ID)
		}
	}
	return strings.Join(ids, ", ")
}

func dbList(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	out, err := c.run(mariadb.ListCmd())
	if err != nil {
		return nil, err
	}
	r := DBList{Schema: "hostops.db-list.v1", Databases: []string{}}
	for _, d := range mariadb.ParseList(out) {
		if c.Has("all") || !mariadb.System[d] {
			r.Databases = append(r.Databases, d)
		}
	}
	return r, nil
}

func dbSize(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	out, err := c.run(mariadb.SizeCmd())
	if err != nil {
		return nil, err
	}
	s := mariadb.ParseSize(out)
	if s == nil {
		s = []mariadb.Size{}
	}
	return DBSize{Schema: "hostops.db-size.v1", Schemas: s}, nil
}

func intFlag(c *Ctx, name string, def, max int) (int, error) {
	v, ok := c.Flags[name]
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, hosterr.New(hosterr.Validation, "--%s must be a number", name)
	}
	return n, validate.Count("--"+name, n, max)
}

func dbSlowlog(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	top, err := intFlag(c, "top", 10, 100)
	if err != nil {
		return nil, err
	}
	out, err := c.run(mariadb.SlowVarsCmd())
	if err != nil {
		return nil, err
	}
	v := mariadb.ParseSlowVars(out)
	r := DBSlowlog{Schema: "hostops.db-slowlog.v1", Settings: v, Queries: []mariadb.SlowQuery{}}
	if !v.Enabled {
		r.Note = "slow_query_log is OFF; enable it (SET GLOBAL slow_query_log=1) before diagnosing"
		return r, nil
	}
	p, err := validate.PathUnder(v.File, "/var/lib/mysql", "/var/log")
	if err != nil {
		return nil, err
	}
	b, err := c.Env.ReadFile(p)
	if err != nil {
		return nil, hosterr.Wrap(hosterr.General, err, "reading slow log")
	}
	b = logs.Tail(b, 200000)
	q := mariadb.ParseSlowLog(b)
	if len(q) > top {
		q = q[:top]
	}
	r.Queries = q
	return r, nil
}

func logsTop(c *Ctx) (any, error) {
	if len(c.Pos) > 1 {
		return nil, c.positional(1)
	}
	lines, err := intFlag(c, "lines", 5000, 1000000)
	if err != nil {
		return nil, err
	}
	top, err := intFlag(c, "top", 10, 100)
	if err != nil {
		return nil, err
	}
	var path string
	switch {
	case c.Flags["file"] != "" && len(c.Pos) == 0:
		p, err := validate.PathUnder(c.Flags["file"], c.Cfg.HomeRoot, "/var/log", "/usr/local/lsws/logs")
		if err != nil {
			return nil, err
		}
		path = p
	case len(c.Pos) == 1 && c.Flags["file"] == "":
		s, err := c.site(c.Pos[0])
		if err != nil {
			return nil, err
		}
		if s.AccessLog == "" {
			return nil, hosterr.New(hosterr.Validation, "site %s has no access log configured", s.Domain)
		}
		path = s.AccessLog
	default:
		return nil, hosterr.New(hosterr.Validation, "usage: hostops logs top <domain> | --file <path>")
	}
	b, err := c.Env.ReadFile(path)
	if err != nil {
		return nil, hosterr.New(hosterr.General, "cannot read %s", path)
	}
	return logs.Summarize(path, logs.Tail(b, lines), top), nil
}

var priorities = map[string]bool{"emerg": true, "alert": true, "crit": true, "err": true, "warning": true, "notice": true, "info": true, "debug": true,
	"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "7": true}

func logsJournal(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	n, err := intFlag(c, "lines", 100, 10000)
	if err != nil {
		return nil, err
	}
	unit := ""
	if u, ok := c.Flags["unit"]; ok {
		if unit, err = validate.Unit(u); err != nil {
			return nil, err
		}
	}
	prio := c.Flags["priority"]
	if prio != "" && !priorities[prio] {
		return nil, hosterr.New(hosterr.Validation, "invalid --priority %q", validate.Printable(prio))
	}
	out, err := c.run(systemd.JournalCmd(unit, n, prio))
	if err != nil {
		return nil, err
	}
	es := systemd.ParseJournal(out)
	if es == nil {
		es = []systemd.JournalEntry{}
	}
	return Journal{Schema: "hostops.journal.v1", Unit: unit, Entries: es}, nil
}

func auditVerify(c *Ctx) (any, error) {
	if err := c.positional(0); err != nil {
		return nil, err
	}
	rep, err := audit.Verify(auditPath(c.Cfg))
	if err != nil {
		return rep, err
	}
	return rep, nil
}

func nonNil(s []adapters.Site) []adapters.Site {
	if s == nil {
		return []adapters.Site{}
	}
	return s
}
