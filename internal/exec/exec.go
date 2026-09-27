// Package exec is the only place hostops starts processes. Every command is a
// declared Command value with an explicit argv slice; there is no shell, no
// string concatenation and no catch-all "run". A Command names an allowlisted
// Binary, and user-derived arguments are marked so they get re-checked here as
// defence in depth even after the typed validators in internal/validate.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/hosterr"
	"github.com/jlugo32/hostops/internal/validate"
)

// Binary is an allowlisted executable. Only the names below can ever run.
type Binary string

const (
	Systemctl      Binary = "systemctl"
	Journalctl     Binary = "journalctl"
	Lswsctrl       Binary = "lswsctrl"
	Nginx          Binary = "nginx"
	Fail2banClient Binary = "fail2ban-client"
	FirewallCmd    Binary = "firewall-cmd"
	AcmeSh         Binary = "acme.sh"
	Certbot        Binary = "certbot"
	Mariadb        Binary = "mariadb"
	Mysqldump      Binary = "mysqldump"
	Cyberpanel     Binary = "cyberpanel"
	Getenforce     Binary = "getenforce"
	Tar            Binary = "tar"
)

// searchPaths fixes where each binary may be found. PATH is never consulted,
// so a writable directory earlier in PATH cannot shadow a real tool.
var searchPaths = map[Binary][]string{
	Systemctl:      {"/usr/bin/systemctl", "/bin/systemctl"},
	Journalctl:     {"/usr/bin/journalctl", "/bin/journalctl"},
	Lswsctrl:       {"/usr/local/lsws/bin/lswsctrl"},
	Nginx:          {"/usr/sbin/nginx", "/usr/bin/nginx"},
	Fail2banClient: {"/usr/bin/fail2ban-client"},
	FirewallCmd:    {"/usr/bin/firewall-cmd"},
	AcmeSh:         {"/root/.acme.sh/acme.sh", "/usr/local/bin/acme.sh"},
	Certbot:        {"/usr/bin/certbot", "/usr/local/bin/certbot", "/snap/bin/certbot"},
	Mariadb:        {"/usr/bin/mariadb", "/usr/bin/mysql"},
	Mysqldump:      {"/usr/bin/mysqldump", "/usr/bin/mariadb-dump"},
	Cyberpanel:     {"/usr/bin/cyberpanel"},
	Getenforce:     {"/usr/sbin/getenforce"},
	Tar:            {"/usr/bin/tar", "/bin/tar"},
}

// Allowed reports whether b is on the allowlist.
func Allowed(b Binary) bool { _, ok := searchPaths[b]; return ok }

// Arg is one argv element. Lit values are compile-time constants written by
// hostops itself (flags, fixed SQL); Param values came from the user and are
// re-validated before execution.
type Arg struct {
	Value string
	Param bool
}

// Lit returns a trusted literal argument.
func Lit(v string) Arg { return Arg{Value: v} }

// Param returns an untrusted, user-derived argument.
func Param(v string) Arg { return Arg{Value: v, Param: true} }

// Command is a fully declared process invocation.
type Command struct {
	ID      string        // stable identifier, e.g. "fail2ban.unban"
	Bin     Binary        // allowlisted executable
	Args    []Arg         // explicit argv (without argv[0])
	Mutates bool          // true for anything that changes host state
	Timeout time.Duration // 0 means DefaultTimeout
}

// DefaultTimeout bounds every command that does not set its own.
const DefaultTimeout = 60 * time.Second

// Argv renders the command for display, logging and fixture lookup.
func (c Command) Argv() []string {
	out := make([]string, 0, len(c.Args)+1)
	out = append(out, string(c.Bin))
	for _, a := range c.Args {
		out = append(out, a.Value)
	}
	return out
}

// String joins Argv with spaces. It is for humans only and is never executed.
func (c Command) String() string { return strings.Join(c.Argv(), " ") }

// Validate checks the command against the allowlist and re-checks every
// user-derived argument for metacharacters.
func (c Command) Validate() error {
	if c.ID == "" {
		return hosterr.New(hosterr.General, "command has no ID")
	}
	if !Allowed(c.Bin) {
		return hosterr.New(hosterr.Validation, "binary %q is not allowlisted", c.Bin)
	}
	for _, a := range c.Args {
		if !a.Param {
			continue
		}
		// '=' and ':' are legitimate inside paths/IPv6 but are still checked by
		// the typed validators; here we refuse the classic shell set.
		for _, r := range a.Value {
			if r < 0x20 || r == 0x7f || strings.ContainsRune("`$;&|<>(){}[]*?!~'\"\\\n", r) {
				return hosterr.New(hosterr.Validation, "argument %q for %s contains a forbidden character", validate.Printable(a.Value), c.ID)
			}
		}
		if strings.HasPrefix(a.Value, "-") {
			return hosterr.New(hosterr.Validation, "argument %q for %s looks like an option", validate.Printable(a.Value), c.ID)
		}
	}
	return nil
}

// Result is what a command produced.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes Commands.
type Runner interface {
	Run(ctx context.Context, c Command) (Result, error)
	// Mode is "live" or "fixture"; it is recorded in the audit log.
	Mode() string
}

// ErrReadOnly is returned when a mutating command reaches a read-only runner.
var ErrReadOnly = hosterr.New(hosterr.Permission, "refusing to run a mutating command in --read-only mode")

// OSRunner runs real processes with a scrubbed environment.
type OSRunner struct {
	ReadOnly bool
	// Sudo runs every command as `sudo -n -- <abs path> <args>` for an
	// unprivileged operator account (deploy/sudoers.d/hostops). -n makes a
	// missing sudoers rule fail instead of prompting.
	Sudo bool
}

// sudoPath is fixed; PATH is never consulted.
const sudoPath = "/usr/bin/sudo"

// ProcessArgv returns the program and arguments OSRunner will execute.
func (r *OSRunner) ProcessArgv(abs string, c Command) (string, []string) {
	args := c.Argv()[1:]
	if r.Sudo {
		return sudoPath, append([]string{"-n", "--", abs}, args...)
	}
	return abs, args
}

func (r *OSRunner) Mode() string { return "live" }

// Resolve finds the absolute path of an allowlisted binary.
func Resolve(b Binary) (string, error) {
	for _, p := range searchPaths[b] {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", hosterr.New(hosterr.General, "%s is not installed in any allowlisted location", b)
}

// Run executes c. It never invokes a shell.
func (r *OSRunner) Run(ctx context.Context, c Command) (Result, error) {
	if err := c.Validate(); err != nil {
		return Result{}, err
	}
	if c.Mutates && r.ReadOnly {
		return Result{}, ErrReadOnly
	}
	path, err := Resolve(c.Bin)
	if err != nil {
		return Result{}, err
	}
	to := c.Timeout
	if to == 0 {
		to = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	prog, argv := r.ProcessArgv(path, c)
	cmd := osexec.CommandContext(ctx, prog, argv...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + os.Getenv("HOME"), "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	res := Result{Stdout: so.Bytes(), Stderr: se.Bytes()}
	var ee *osexec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return res, hosterr.New(hosterr.General, "%s timed out after %s", c.ID, to)
	default:
		return res, hosterr.Wrap(hosterr.General, err, fmt.Sprintf("starting %s", c.ID))
	}
	return res, nil
}
