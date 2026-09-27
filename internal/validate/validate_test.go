package validate

import (
	"testing"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// injection is the shared hostile-input corpus. Every validator must reject
// every entry with exit code 3.
var injection = []string{
	"example.com; rm -rf /",
	"example.com && reboot",
	"example.com|nc evil 1",
	"$(id)", "`id`", "${IFS}", "a>b", "a<b",
	"example.com\nFAKE LOG LINE", "x\r\ny", "tab\there", "nul\x00byte",
	"--help", "-rf", "--confirm=abc",
	"../../etc/passwd", "..", "a/../b",
	"sshd.service;reboot", "lsws.service\nExecStart=/bin/sh",
	"\x1b[31mred", "é.com", "x'y", `x"y`, `a\b`, "a*b", "a?b", "",
}

func TestInjectionCorpusFailsClosed(t *testing.T) {
	type check struct {
		name string
		fn   func(string) error
	}
	checks := []check{
		{"domain", func(v string) error { _, err := Domain(v); return err }},
		{"unit", func(v string) error { _, err := Unit(v); return err }},
		{"ip", func(v string) error { _, err := IP(v); return err }},
		{"ident", func(v string) error { _, err := Ident("jail", v); return err }},
		{"filename", func(v string) error { _, err := FileName(v); return err }},
		{"path", func(v string) error { _, err := PathUnder(v, "/home"); return err }},
	}
	for _, c := range checks {
		for _, in := range injection {
			err := c.fn(in)
			if err == nil {
				t.Errorf("%s accepted hostile input %q", c.name, in)
				continue
			}
			if hosterr.Code(err) != hosterr.Validation {
				t.Errorf("%s(%q) exit %d, want 3", c.name, in, hosterr.Code(err))
			}
		}
	}
}

func TestAcceptsLegitimate(t *testing.T) {
	for _, d := range []string{"example.com", "Sub.Example.CO.uk", "a-b.io"} {
		if _, err := Domain(d); err != nil {
			t.Errorf("Domain(%q): %v", d, err)
		}
	}
	for _, u := range []string{"lsws", "lsws.service", "php-fpm@8.5.service", "mariadb"} {
		if _, err := Unit(u); err != nil {
			t.Errorf("Unit(%q): %v", u, err)
		}
	}
	for _, ip := range []string{"203.0.113.7", "2001:db8::1"} {
		if _, err := IP(ip); err != nil {
			t.Errorf("IP(%q): %v", ip, err)
		}
	}
	if _, err := PathUnder("/home/example.com/backup/backup-example.com-09.01.2026_03-00-00.tar.gz", "/home"); err != nil {
		t.Errorf("PathUnder: %v", err)
	}
}

func TestPathUnderRejectsSiblingPrefix(t *testing.T) {
	if _, err := PathUnder("/homeevil/x", "/home"); err == nil {
		t.Fatal("accepted /homeevil as inside /home")
	}
	if _, err := PathUnder("/home", "/home"); err == nil {
		t.Fatal("accepted the root itself")
	}
}

func TestPrintableEscapesControls(t *testing.T) {
	got := Printable("a\nb\x1bc")
	if got != `a\x0ab\x1bc` {
		t.Fatalf("Printable = %q", got)
	}
}
