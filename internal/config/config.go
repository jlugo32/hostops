// Package config resolves settings with the precedence
// flags > environment > /etc/hostops/config.toml > $XDG_CONFIG_HOME/hostops/config.toml > defaults.
// Secrets are never read from flags: database access relies on the invoking
// user's ~/.my.cnf or unix-socket auth, which hostops never sees.
package config

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/BurntSushi/toml"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// Config is the resolved configuration.
type Config struct {
	Adapter   string `toml:"adapter"`    // openlitespeed | cyberpanel | nginx
	ReadOnly  bool   `toml:"read_only"`  // drop write commands entirely
	Root      string `toml:"root"`       // filesystem prefix (tests point this at a fake host tree)
	OLSRoot   string `toml:"ols_root"`   // /usr/local/lsws
	NginxRoot string `toml:"nginx_root"` // /etc/nginx
	HomeRoot  string `toml:"home_root"`  // /home
	LELive    string `toml:"le_live"`    // /etc/letsencrypt/live
	AcmeHome  string `toml:"acme_home"`  // /root/.acme.sh
	BackupDir string `toml:"backup_dir"` // generic backups for non-CyberPanel hosts
	AuditLog  string `toml:"audit_log"`
	// ProtectedIPs are never banned (addresses or CIDR prefixes): your office,
	// monitoring, the panel's own health checks.
	ProtectedIPs []string `toml:"protected_ips"`
	// UseSudo runs commands through `sudo -n` (see deploy/sudoers.d/hostops).
	UseSudo  bool     `toml:"use_sudo"`
	Fixtures string   `toml:"-"` // env only: HOSTOPS_FIXTURES
	Sources  []string `toml:"-"`
}

// Defaults for AlmaLinux 9 + CyberPanel + OpenLiteSpeed.
func Defaults() Config {
	return Config{
		Adapter:   "cyberpanel",
		Root:      "/",
		OLSRoot:   "/usr/local/lsws",
		NginxRoot: "/etc/nginx",
		HomeRoot:  "/home",
		LELive:    "/etc/letsencrypt/live",
		AcmeHome:  "/root/.acme.sh",
		BackupDir: "/var/backups/hostops",
	}
}

// Files returns config files lowest precedence first.
func Files() []string {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		if h, err := os.UserHomeDir(); err == nil {
			xdg = filepath.Join(h, ".config")
		}
	}
	sys := "/etc/hostops/config.toml"
	if v := os.Getenv("HOSTOPS_SYSTEM_CONFIG"); v != "" {
		sys = v // test hook
	}
	return []string{filepath.Join(xdg, "hostops", "config.toml"), sys}
}

// Load applies files then environment. Flags are applied by the caller.
func Load() (Config, error) {
	c := Defaults()
	for _, f := range Files() {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		md, err := toml.DecodeFile(f, &c)
		if err != nil {
			return c, hosterr.Wrap(hosterr.Validation, err, "parsing "+f)
		}
		if und := md.Undecoded(); len(und) > 0 {
			return c, hosterr.New(hosterr.Validation, "%s: unknown key %q", f, und[0].String())
		}
		c.Sources = append(c.Sources, f)
	}
	env := func(k string, dst *string) {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			*dst = v
		}
	}
	env("HOSTOPS_ADAPTER", &c.Adapter)
	env("HOSTOPS_ROOT", &c.Root)
	env("HOSTOPS_AUDIT_LOG", &c.AuditLog)
	env("HOSTOPS_FIXTURES", &c.Fixtures)
	if c.Fixtures == "" {
		// `claude plugin eval` only forwards EVAL_* variables to the agent.
		env("EVAL_HOSTOPS_FIXTURES", &c.Fixtures)
	}
	if v := os.Getenv("HOSTOPS_READ_ONLY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return c, hosterr.New(hosterr.Validation, "HOSTOPS_READ_ONLY=%q is not a boolean", v)
		}
		c.ReadOnly = c.ReadOnly || b
	}
	if c.Fixtures != "" && !filepath.IsAbs(c.Fixtures) {
		// Relative fixture paths (used by the eval corpus) resolve against
		// HOSTOPS_REPO, else the repo containing this binary (bin/hostops).
		base := os.Getenv("HOSTOPS_REPO")
		if base == "" {
			if exe, err := os.Executable(); err == nil {
				if r, err := filepath.EvalSymlinks(exe); err == nil {
					exe = r
				}
				base = filepath.Dir(filepath.Dir(exe))
			}
		}
		c.Fixtures = filepath.Join(base, c.Fixtures)
	}
	if c.Fixtures != "" && c.AuditLog == "" {
		// Fixture runs (tests, evals) never write the operator's real audit
		// log. Each eval run has its own working directory, so a relative log
		// keeps single-use tokens from leaking between runs.
		c.AuditLog = ".hostops-audit.jsonl"
		env("EVAL_HOSTOPS_AUDIT_LOG", &c.AuditLog)
	}
	if c.Fixtures != "" && c.Root == "/" {
		// A fixture directory doubles as the fake host filesystem.
		c.Root = filepath.Join(c.Fixtures, "root")
	}
	return c, nil
}

// Path joins a host-absolute path onto Root.
func (c Config) Path(p string) string {
	if c.Root == "" || c.Root == "/" {
		return p
	}
	return filepath.Join(c.Root, p)
}
