// Package baseline runs read-only hardening checks for an AlmaLinux 9 web
// host. Each check names the NSA/CISA misconfiguration it guards against
// (joint advisory AA23-278A, "Top Ten Cybersecurity Misconfigurations") and
// proposes a fix; it never applies one. docs/threat-model.md maps the same
// items to hostops's own code paths.
package baseline

import (
	"context"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/exec"
)

// Status of a check.
const (
	Pass    = "pass"
	Warn    = "warn"
	Fail    = "fail"
	Unknown = "unknown"
)

// Check is one result.
type Check struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Control  string `json:"control"`
	Fix      string `json:"proposed_fix,omitempty"`
}

// Report is the baseline output.
type Report struct {
	Schema  string         `json:"schema"`
	Summary map[string]int `json:"summary"`
	Checks  []Check        `json:"checks"`
}

// sshdConfig merges sshd_config and sshd_config.d/*.conf. sshd uses the
// FIRST value it sees for a keyword, and Include of sshd_config.d normally
// comes first, so drop-ins are read before the main file.
func sshdConfig(env adapters.Env) (map[string]string, bool) {
	files, _ := filepath.Glob(env.Path("/etc/ssh/sshd_config.d/*.conf"))
	var hostFiles []string
	for _, f := range files {
		hostFiles = append(hostFiles, "/"+strings.TrimPrefix(strings.TrimPrefix(f, env.Path("/")), "/"))
	}
	hostFiles = append(hostFiles, "/etc/ssh/sshd_config")
	kv := map[string]string{}
	found := false
	for _, f := range hostFiles {
		b, err := env.ReadFile(f)
		if err != nil {
			continue
		}
		found = true
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if strings.HasPrefix(strings.ToLower(l), "match ") {
				break // settings below Match are conditional
			}
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			k := strings.ToLower(f[0])
			if _, ok := kv[k]; !ok {
				kv[k] = strings.ToLower(f[1])
			}
		}
	}
	return kv, found
}

func run(ctx context.Context, env adapters.Env, c exec.Command) (string, int, bool) {
	r, err := env.Exec(ctx, c)
	if err != nil || r.ExitCode == 127 {
		return "", -1, false
	}
	return strings.TrimSpace(string(r.Stdout)), r.ExitCode, true
}

// Run executes every check. docRoots are scanned for secrets files.
func Run(ctx context.Context, env adapters.Env, docRoots []string) Report {
	var cs []Check
	add := func(c Check) { cs = append(cs, c) }

	kv, ok := sshdConfig(env)
	if !ok {
		add(Check{ID: "HO-SSH-01", Title: "SSH root login restricted", Status: Unknown, Evidence: "sshd_config not readable", Control: "AA23-278A #2 improper separation of user/administrator privilege"})
	} else {
		prl := kv["permitrootlogin"]
		if prl == "" {
			prl = "prohibit-password (default)"
		}
		st := Pass
		if prl == "yes" {
			st = Fail
		}
		add(Check{ID: "HO-SSH-01", Title: "SSH root login restricted", Status: st, Evidence: "PermitRootLogin " + prl,
			Control: "AA23-278A #2 improper separation of user/administrator privilege", Fix: "set PermitRootLogin prohibit-password (key-only) in /etc/ssh/sshd_config.d/00-hostops.conf"})
		pa := kv["passwordauthentication"]
		st = Pass
		if pa != "no" {
			st = Fail
		}
		if pa == "" {
			pa = "yes (default)"
		}
		add(Check{ID: "HO-SSH-02", Title: "SSH password authentication disabled", Status: st, Evidence: "PasswordAuthentication " + pa,
			Control: "AA23-278A #7 weak or misconfigured MFA / #9 poor credential hygiene", Fix: "set PasswordAuthentication no after confirming key login works in a second session"})
		mat := kv["maxauthtries"]
		n, err := strconv.Atoi(mat)
		st = Pass
		if mat == "" || err != nil || n > 4 {
			st = Warn
		}
		if mat == "" {
			mat = "6 (default)"
		}
		add(Check{ID: "HO-SSH-03", Title: "SSH MaxAuthTries <= 4", Status: st, Evidence: "MaxAuthTries " + mat,
			Control: "AA23-278A #9 poor credential hygiene", Fix: "set MaxAuthTries 4"})
	}

	if out, code, ok := run(ctx, env, exec.Command{ID: "baseline.firewalld", Bin: exec.FirewallCmd, Args: []exec.Arg{exec.Lit("--state")}}); !ok {
		add(Check{ID: "HO-FW-01", Title: "Host firewall running", Status: Unknown, Evidence: "firewall-cmd unavailable", Control: "AA23-278A #4 lack of network segmentation"})
	} else {
		st := Pass
		if code != 0 || out != "running" {
			st = Fail
		}
		add(Check{ID: "HO-FW-01", Title: "Host firewall running", Status: st, Evidence: "firewall-cmd --state: " + out,
			Control: "AA23-278A #4 lack of network segmentation", Fix: "systemctl enable --now firewalld (from a console session, not SSH, the first time)"})
	}

	if out, _, ok := run(ctx, env, exec.Command{ID: "baseline.fail2ban", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("is-active"), exec.Lit("fail2ban")}}); ok {
		st := Pass
		if out != "active" {
			st = Fail
		}
		add(Check{ID: "HO-F2B-01", Title: "fail2ban active", Status: st, Evidence: "fail2ban: " + out,
			Control: "AA23-278A #3 insufficient internal network monitoring", Fix: "systemctl enable --now fail2ban; ensure the sshd jail is enabled"})
	}

	if out, _, ok := run(ctx, env, exec.Command{ID: "baseline.selinux", Bin: exec.Getenforce}); ok {
		st := map[string]string{"Enforcing": Pass, "Permissive": Warn, "Disabled": Fail}[out]
		if st == "" {
			st = Unknown
		}
		add(Check{ID: "HO-SEL-01", Title: "SELinux enforcing", Status: st, Evidence: "getenforce: " + out,
			Control: "AA23-278A #10 unrestricted code execution", Fix: "fix denials with audit2why before switching to enforcing; CyberPanel ships permissive"})
	}

	if out, _, ok := run(ctx, env, exec.Command{ID: "baseline.autoupdate", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("is-enabled"), exec.Lit("dnf-automatic.timer")}}); ok {
		st := Pass
		if out != "enabled" {
			st = Warn
		}
		add(Check{ID: "HO-UPD-01", Title: "Automatic security updates", Status: st, Evidence: "dnf-automatic.timer: " + out,
			Control: "AA23-278A #5 poor patch management", Fix: "dnf install dnf-automatic; set upgrade_type = security; systemctl enable --now dnf-automatic.timer"})
	}

	var exposed []string
	for _, root := range docRoots {
		base := env.Path(root)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && strings.Count(strings.TrimPrefix(p, base), "/") >= 2 {
				return filepath.SkipDir
			}
			n := d.Name()
			if !d.IsDir() && (n == "config.php" || n == ".env" || n == "wp-config.php") {
				hostPath := "/" + strings.TrimPrefix(strings.TrimPrefix(p, env.Path("/")), "/")
				if info, err := d.Info(); err == nil && env.Perm(hostPath, info)&0o004 != 0 {
					exposed = append(exposed, hostPath)
				}
			}
			return nil
		})
	}
	st, ev := Pass, "no world-readable config.php/.env/wp-config.php in site roots"
	if len(exposed) > 0 {
		st, ev = Fail, "world-readable: "+strings.Join(exposed, ", ")
	}
	add(Check{ID: "HO-PERM-01", Title: "Secrets files not world-readable", Status: st, Evidence: ev,
		Control: "AA23-278A #8 insufficient ACLs on data / #9 poor credential hygiene", Fix: "chown <siteuser>:<siteuser> <file> && chmod 600 <file>"})

	r := Report{Schema: "hostops.baseline.v1", Summary: map[string]int{Pass: 0, Warn: 0, Fail: 0, Unknown: 0}, Checks: cs}
	for _, c := range cs {
		r.Summary[c.Status]++
	}
	return r
}

// Table renders the report for humans.
func (r Report) Table() ([]string, [][]string) {
	rows := make([][]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		rows = append(rows, []string{c.ID, c.Status, c.Title, c.Evidence})
	}
	return []string{"ID", "STATUS", "CHECK", "EVIDENCE"}, rows
}
