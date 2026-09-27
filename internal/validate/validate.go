// Package validate holds the typed validators every user-supplied parameter
// passes through before it can reach internal/exec. All validators fail
// closed: anything not positively recognised is rejected with exit code 3.
package validate

import (
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// ShellMeta lists characters that never appear in a legitimate hostops
// parameter. Commands never pass through a shell, so this is defence in
// depth: a value containing any of these is refused outright.
const ShellMeta = "`$;&|<>(){}[]*?!~'\"\\#%^=,\x00"

var (
	domainRE = regexp.MustCompile(`^(?i)(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	unitRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}$`)
	identRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	fileRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,254}$`)
)

func fail(what, v, why string) error {
	return hosterr.New(hosterr.Validation, "invalid %s %q: %s", what, Printable(v), why)
}

// Printable renders v safely for diagnostics: control characters are escaped
// so a malicious parameter cannot forge terminal output or log lines.
func Printable(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x`)
			b.WriteString(strings.ToLower(string("0123456789ABCDEF"[r>>4])))
			b.WriteString(strings.ToLower(string("0123456789ABCDEF"[r&0xf])))
		case r >= 0x80 && r < 0xa0:
			b.WriteString(`\u`)
		default:
			b.WriteRune(r)
		}
	}
	if len(v) > 80 {
		return b.String()[:80] + "…"
	}
	return b.String()
}

// NoMeta rejects shell metacharacters, control bytes, leading dashes and
// empty values. It is the base check applied to every free-form value.
func NoMeta(what, v string) error {
	if v == "" {
		return fail(what, v, "empty")
	}
	if strings.HasPrefix(v, "-") {
		return fail(what, v, "must not start with '-' (option injection)")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fail(what, v, "control character")
		}
		if strings.ContainsRune(ShellMeta, r) {
			return fail(what, v, "shell metacharacter")
		}
		if r > 0x7e {
			return fail(what, v, "non-ASCII character")
		}
	}
	return nil
}

// Domain validates a DNS hostname (lower-cased on return).
func Domain(v string) (string, error) {
	if err := NoMeta("domain", v); err != nil {
		return "", err
	}
	if len(v) > 253 || !domainRE.MatchString(v) {
		return "", fail("domain", v, "not a hostname")
	}
	return strings.ToLower(v), nil
}

// Unit validates a systemd unit name. Path-like and templated escape forms
// that systemd would interpret specially are refused.
func Unit(v string) (string, error) {
	if err := NoMeta("unit", v); err != nil {
		return "", err
	}
	if strings.Contains(v, "/") || strings.Contains(v, "..") || !unitRE.MatchString(v) {
		return "", fail("unit", v, "not a unit name")
	}
	return v, nil
}

// IP validates a single IPv4/IPv6 address (no CIDR, no zone).
func IP(v string) (netip.Addr, error) {
	if err := NoMeta("ip", v); err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fail("ip", v, "not an IP address")
	}
	return a, nil
}

// Ident validates a short identifier: jail names, database names, adapters.
func Ident(what, v string) (string, error) {
	if err := NoMeta(what, v); err != nil {
		return "", err
	}
	if !identRE.MatchString(v) {
		return "", fail(what, v, "letters, digits, '_' and '-' only")
	}
	return v, nil
}

// FileName validates a bare file name (no directory part).
func FileName(v string) (string, error) {
	if err := NoMeta("file name", v); err != nil {
		return "", err
	}
	if strings.Contains(v, "/") || strings.Contains(v, "..") || !fileRE.MatchString(v) {
		return "", fail("file name", v, "bare file name only")
	}
	return v, nil
}

// PathUnder validates that p is an absolute, clean path strictly inside one
// of the allowed roots. Traversal ("..") and relative paths are refused even
// when they would resolve inside a root.
func PathUnder(p string, roots ...string) (string, error) {
	if err := NoMeta("path", p); err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		return "", fail("path", p, "must be absolute")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", fail("path", p, "path traversal")
		}
	}
	c := filepath.Clean(p)
	for _, r := range roots {
		r = filepath.Clean(r)
		if strings.HasPrefix(c, r+"/") {
			return c, nil
		}
	}
	return "", fail("path", p, "outside allowed roots "+strings.Join(roots, ", "))
}

// Count validates a small positive integer flag such as --lines.
func Count(what string, n, max int) error {
	if n < 1 || n > max {
		return hosterr.New(hosterr.Validation, "invalid %s %d: must be 1..%d", what, n, max)
	}
	return nil
}
