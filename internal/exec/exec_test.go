package exec

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jlugo32/hostops/internal/hosterr"
)

func TestValidateRejectsNonAllowlisted(t *testing.T) {
	c := Command{ID: "x", Bin: Binary("sh"), Args: []Arg{Lit("-c"), Lit("id")}}
	if hosterr.Code(c.Validate()) != hosterr.Validation {
		t.Fatal("sh must not be allowlisted")
	}
	for _, b := range []Binary{"bash", "sh", "python3", "curl", "rm"} {
		if Allowed(b) {
			t.Errorf("%s is allowlisted", b)
		}
	}
}

func TestValidateRejectsParamInjection(t *testing.T) {
	for _, bad := range []string{"a;b", "$(id)", "`id`", "a|b", "a\nb", "-x", "a>b", "a&b"} {
		c := Command{ID: "t", Bin: Systemctl, Args: []Arg{Lit("status"), Param(bad)}}
		if hosterr.Code(c.Validate()) != hosterr.Validation {
			t.Errorf("param %q accepted", bad)
		}
	}
	// Literals may contain SQL punctuation because hostops wrote them.
	ok := Command{ID: "t", Bin: Mariadb, Args: []Arg{Lit("-e"), Lit("SELECT SUM(x) FROM t;")}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("literal rejected: %v", err)
	}
}

func TestReadOnlyBlocksMutation(t *testing.T) {
	r := NewFixtureRunner(t.TempDir(), true)
	_, err := r.Run(context.Background(), Command{ID: "svc.restart", Bin: Systemctl, Args: []Arg{Lit("restart"), Param("lsws")}, Mutates: true})
	if hosterr.Code(err) != hosterr.Permission {
		t.Fatalf("want exit 2, got %v", err)
	}
	o := &OSRunner{ReadOnly: true}
	_, err = o.Run(context.Background(), Command{ID: "svc.restart", Bin: Systemctl, Args: []Arg{Lit("restart"), Param("lsws")}, Mutates: true})
	if hosterr.Code(err) != hosterr.Permission {
		t.Fatalf("OSRunner: want exit 2, got %v", err)
	}
}

func TestFixtureAfterMutation(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "commands.json"), []byte(`{
	 "commands": {"systemctl is-active lsws": {"stdout": "failed\n", "exit": 3}},
	 "after_mutation": {"systemctl is-active lsws": {"stdout": "active\n"}}}`), 0o600)
	r := NewFixtureRunner(dir, false)
	ctx := context.Background()
	st := Command{ID: "s", Bin: Systemctl, Args: []Arg{Lit("is-active"), Param("lsws")}}
	res, _ := r.Run(ctx, st)
	if string(res.Stdout) != "failed\n" || res.ExitCode != 3 {
		t.Fatalf("before: %q %d", res.Stdout, res.ExitCode)
	}
	r.Run(ctx, Command{ID: "r", Bin: Systemctl, Args: []Arg{Lit("restart"), Param("lsws")}, Mutates: true})
	res, _ = r.Run(ctx, st)
	if string(res.Stdout) != "active\n" {
		t.Fatalf("after: %q", res.Stdout)
	}
	if !r.Mutated() {
		t.Fatal("Mutated() false")
	}
}

func TestFixtureUnknownReadIs127(t *testing.T) {
	r := NewFixtureRunner(t.TempDir(), false)
	res, err := r.Run(context.Background(), Command{ID: "x", Bin: Systemctl, Args: []Arg{Lit("status")}})
	if err != nil || res.ExitCode != 127 {
		t.Fatalf("got %v %d", err, res.ExitCode)
	}
}

func TestLive_OSRunnerRunsSystemctlVersion(t *testing.T) {
	if os.Getenv("HOSTOPS_LIVE") != "1" {
		t.Skip("HOSTOPS_LIVE!=1: skipping test that starts a real process")
	}
	r := &OSRunner{}
	res, err := r.Run(context.Background(), Command{ID: "sc.version", Bin: Systemctl, Args: []Arg{Lit("--version")}})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("systemctl --version: %v %d", err, res.ExitCode)
	}
}
