package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// FixtureRunner answers commands from a directory of canned outputs instead
// of starting processes. It powers unit tests, testscript end-to-end tests
// and the eval corpus; it never touches the host.
//
// Layout: <dir>/commands.json maps an argv string (Command.String()) to a
// response. "stdout_file" is relative to <dir>. A response listed under
// "after_mutation" replaces the normal one once any mutating command has run
// in this process, so tests can model "state after the fix".
type FixtureRunner struct {
	Dir      string
	ReadOnly bool

	mu       sync.Mutex
	loaded   bool
	table    fixtureTable
	mutated  bool
	Calls    []string
	callsLog string
}

type fixtureResp struct {
	Stdout     string `json:"stdout"`
	StdoutFile string `json:"stdout_file"`
	Stderr     string `json:"stderr"`
	Exit       int    `json:"exit"`
}

type fixtureTable struct {
	Commands      map[string]fixtureResp `json:"commands"`
	AfterMutation map[string]fixtureResp `json:"after_mutation"`
}

// NewFixtureRunner returns a runner over dir. If HOSTOPS_FIXTURE_CALLS names
// a file, every executed argv is appended to it so tests can assert exactly
// what would have run.
func NewFixtureRunner(dir string, readOnly bool) *FixtureRunner {
	return &FixtureRunner{Dir: dir, ReadOnly: readOnly, callsLog: os.Getenv("HOSTOPS_FIXTURE_CALLS")}
}

func (r *FixtureRunner) Mode() string { return "fixture" }

// Mutated reports whether a mutating command has run.
func (r *FixtureRunner) Mutated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutated
}

func (r *FixtureRunner) load() error {
	if r.loaded {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, "commands.json"))
	if err != nil {
		if os.IsNotExist(err) {
			r.loaded = true
			return nil
		}
		return hosterr.Wrap(hosterr.General, err, "reading fixture table")
	}
	if err := json.Unmarshal(b, &r.table); err != nil {
		return hosterr.Wrap(hosterr.General, err, "parsing fixture table")
	}
	r.loaded = true
	return nil
}

func (r *FixtureRunner) Run(_ context.Context, c Command) (Result, error) {
	if err := c.Validate(); err != nil {
		return Result{}, err
	}
	if c.Mutates && r.ReadOnly {
		return Result{}, ErrReadOnly
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return Result{}, err
	}
	key := c.String()
	r.Calls = append(r.Calls, key)
	if r.callsLog != "" {
		if f, err := os.OpenFile(r.callsLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprintf(f, "%s\t%s\n", map[bool]string{true: "WRITE", false: "READ"}[c.Mutates], key)
			f.Close()
		}
	}
	resp, ok := fixtureResp{}, false
	if r.mutated {
		resp, ok = r.table.AfterMutation[key]
	}
	if !ok {
		resp, ok = r.table.Commands[key]
	}
	if c.Mutates {
		r.mutated = true
	}
	if !ok {
		if c.Mutates {
			// Mutations succeed silently unless a fixture says otherwise.
			return Result{}, nil
		}
		return Result{ExitCode: 127, Stderr: []byte("no fixture for: " + key)}, nil
	}
	out := resp.Stdout
	if resp.StdoutFile != "" {
		p := filepath.Join(r.Dir, filepath.Clean("/"+resp.StdoutFile))
		b, err := os.ReadFile(p)
		if err != nil {
			return Result{}, hosterr.Wrap(hosterr.General, err, "reading fixture output")
		}
		out = string(b)
	}
	return Result{Stdout: []byte(out), Stderr: []byte(resp.Stderr), ExitCode: resp.Exit}, nil
}

// Joined is a helper for tests.
func (r *FixtureRunner) Joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.Calls, "\n")
}
