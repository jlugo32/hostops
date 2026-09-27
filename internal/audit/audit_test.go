package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlugo32/hostops/internal/hosterr"
)

func newLog(t *testing.T) *Log {
	return &Log{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
}

func TestChainAppendAndVerify(t *testing.T) {
	l := newLog(t)
	for i := 0; i < 5; i++ {
		if _, err := l.Append(Entry{Command: "cert status", Argv: []string{"cert", "status", "example.com"}}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Verify(l.Path)
	if err != nil || !rep.OK || rep.Entries != 5 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	b, _ := os.ReadFile(l.Path)
	first := strings.SplitN(string(b), "\n", 2)[0]
	if !strings.Contains(first, `"prev_sha256":"`+Genesis+`"`) {
		t.Fatalf("first entry not anchored to genesis: %s", first)
	}
}

func TestTamperDetected(t *testing.T) {
	cases := map[string]func([]string) []string{
		"edit":    func(l []string) []string { l[1] = strings.Replace(l[1], `"exit_code":0`, `"exit_code":1`, 1); return l },
		"delete":  func(l []string) []string { return append(l[:1], l[2:]...) },
		"reorder": func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"garbage": func(l []string) []string { l[2] = "not json"; return l },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l := newLog(t)
			for i := 0; i < 4; i++ {
				l.Append(Entry{Command: "x", Argv: []string{"x"}})
			}
			b, _ := os.ReadFile(l.Path)
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			lines = mutate(lines)
			os.WriteFile(l.Path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
			rep, err := Verify(l.Path)
			if hosterr.Code(err) != hosterr.Verification || rep.OK {
				t.Fatalf("tamper %s not detected: %+v %v", name, rep, err)
			}
		})
	}
}

func TestLogLineInjectionNeutralized(t *testing.T) {
	l := newLog(t)
	hostile := []string{
		"example.com\n{\"ts\":\"forged\",\"command\":\"fake\"}",
		"a\r\nb", "\x1b[2J\x1b[H", "nul\x00", "bidi‮evil", "ls x", string([]byte{0xff, 0xfe}),
	}
	for _, h := range hostile {
		if _, err := l.Append(Entry{Command: "sites get", Argv: []string{"sites", "get", h}, ConfirmToken: h}); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(l.Path)
	if n := bytes.Count(b, []byte("\n")); n != len(hostile) {
		t.Fatalf("injection produced %d lines, want %d", n, len(hostile))
	}
	for _, bad := range []string{"\x1b", "\r", "\x00", "‮", " "} {
		if bytes.Contains(b, []byte(bad)) {
			t.Errorf("raw %q survived into the log", bad)
		}
	}
	if rep, err := Verify(l.Path); err != nil || !rep.OK {
		t.Fatalf("chain broken by hostile input: %v", err)
	}
}

func TestVerifyMissingFileIsEmptyOK(t *testing.T) {
	rep, err := Verify(filepath.Join(t.TempDir(), "none.jsonl"))
	if err != nil || !rep.OK || rep.Entries != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestLongLastLine(t *testing.T) {
	l := newLog(t)
	big := strings.Repeat("a", 9000)
	l.Append(Entry{Command: "x", Argv: []string{big}})
	l.Append(Entry{Command: "y", Argv: []string{"y"}})
	if _, err := Verify(l.Path); err != nil {
		t.Fatal(err)
	}
}
