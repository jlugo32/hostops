package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/jlugo32/hostops/internal/cli"
	"github.com/jlugo32/hostops/internal/output"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"hostops": func() int {
			app := &cli.App{Stdout: os.Stdout, Stderr: os.Stderr, StdoutTTY: output.IsTTY(os.Stdout), StderrTTY: output.IsTTY(os.Stderr)}
			return app.Run(os.Args[1:])
		},
	}))
}

// TestScripts runs every testdata/script/*.txtar against the real binary with
// fixture hosts: no command ever reaches the machine running the tests.
func TestScripts(t *testing.T) {
	hosts, err := filepath.Abs("../../testdata/hosts")
	if err != nil {
		t.Fatal(err)
	}
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Setup: func(e *testscript.Env) error {
			e.Setenv("HOSTS", hosts)
			e.Setenv("HOSTOPS_FIXTURES", filepath.Join(hosts, "base"))
			e.Setenv("HOSTOPS_NOW", "2026-09-27T12:00:00Z")
			e.Setenv("HOSTOPS_AUDIT_LOG", filepath.Join(e.WorkDir, "audit.jsonl"))
			e.Setenv("HOSTOPS_SYSTEM_CONFIG", filepath.Join(e.WorkDir, "no-system-config.toml"))
			e.Setenv("HOSTOPS_FIXTURE_CALLS", filepath.Join(e.WorkDir, "calls.log"))
			e.Setenv("XDG_CONFIG_HOME", filepath.Join(e.WorkDir, "xdg"))
			e.Setenv("SSH_CLIENT", "")
			e.Setenv("SSH_CONNECTION", "")
			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// savetoken reads the last stdout (a dry-run plan) into $TOKEN.
			"savetoken": func(ts *testscript.TestScript, neg bool, args []string) {
				var d struct {
					Token string `json:"confirm_token"`
				}
				if err := json.Unmarshal([]byte(ts.ReadFile("stdout")), &d); err != nil || d.Token == "" {
					ts.Fatalf("no confirm_token in stdout: %v", err)
				}
				ts.Setenv("TOKEN", d.Token)
			},
		},
	})
}
