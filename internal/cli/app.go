// Package cli implements the hostops command surface. There is deliberately
// no generic "run"/"exec"/"shell" command: every command below builds typed
// exec.Command values (ADR-0002).
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/adapters/certs"
	"github.com/jlugo32/hostops/internal/adapters/cyberpanel"
	"github.com/jlugo32/hostops/internal/adapters/nginx"
	"github.com/jlugo32/hostops/internal/adapters/openlitespeed"
	"github.com/jlugo32/hostops/internal/audit"
	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/confirm"
	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/hosterr"
	"github.com/jlugo32/hostops/internal/output"
	"github.com/jlugo32/hostops/internal/validate"
)

// Version is set by main via ldflags.
var Version = "dev"

// flagSpec says whether a flag takes a value.
type flagSpec struct {
	value bool
	help  string
}

var globalFlags = map[string]flagSpec{
	"json":      {false, "force JSON output (default when stdout is not a TTY)"},
	"plain":     {false, "tab-separated rows, no headers"},
	"no-color":  {false, "disable colour (also NO_COLOR)"},
	"no-input":  {false, "never prompt (hostops never prompts; accepted for scripts)"},
	"q":         {false, "quiet: suppress diagnostics on stderr"},
	"quiet":     {false, "same as -q"},
	"adapter":   {true, "openlitespeed | cyberpanel | nginx"},
	"read-only": {false, "remove write commands from help and execution"},
	"help":      {false, "show help"},
	"h":         {false, "show help"},
	"version":   {false, "print version"},
}

// Command is one leaf command.
type Command struct {
	Path    string // e.g. "cert renew"
	Args    string // usage of positionals
	Summary string
	Write   bool
	Flags   map[string]flagSpec
	Run     func(c *Ctx) (any, error)
}

// Ctx carries everything a command needs.
type Ctx struct {
	context.Context
	App     *App
	Cmd     *Command
	Pos     []string
	Flags   map[string]string
	Env     adapters.Env
	Out     *output.Printer
	Cfg     config.Config
	Web     adapters.WebServer
	Panel   adapters.Panel
	dryRun  bool
	confirm string
	result  []byte // bytes hashed into the audit log
	token   string
}

// Has reports whether a boolean flag was set.
func (c *Ctx) Has(name string) bool {
	v, ok := c.Flags[name]
	return ok && v != "false"
}

// App is the process-level entry point, parameterised for tests.
type App struct {
	Stdout, Stderr io.Writer
	StdoutTTY      bool
	StderrTTY      bool
	Now            func() time.Time
}

// parse splits args into command words, positionals and flags.
func parse(args []string, extra map[string]flagSpec) (words []string, flags map[string]string, err error) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			words = append(words, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			words = append(words, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		val, hasVal := "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, val, hasVal = k, v, true
		}
		spec, ok := globalFlags[name]
		if !ok {
			spec, ok = extra[name]
		}
		if !ok {
			return nil, nil, hosterr.New(hosterr.Validation, "unknown flag %s", validate.Printable("--"+name))
		}
		if spec.value && !hasVal {
			if i+1 >= len(args) {
				return nil, nil, hosterr.New(hosterr.Validation, "flag --%s needs a value", name)
			}
			i++
			val = args[i]
		}
		if !spec.value && !hasVal {
			val = "true"
		}
		flags[name] = val
	}
	return words, flags, nil
}

// allCommandFlags is the union of every command's flags, used for the first
// parse pass before the command is known.
func allCommandFlags() map[string]flagSpec {
	m := map[string]flagSpec{}
	for _, c := range registry() {
		for k, v := range c.Flags {
			m[k] = v
		}
	}
	return m
}

// Run executes args (os.Args[1:]) and returns the exit code.
func (a *App) Run(args []string) int {
	words, flags, err := parse(args, allCommandFlags())
	pr := output.New(a.Stdout, a.Stderr, a.StdoutTTY, a.StderrTTY, output.Options{
		JSON: flags["json"] == "true", Plain: flags["plain"] == "true", NoColor: flags["no-color"] == "true",
		Quiet: flags["q"] == "true" || flags["quiet"] == "true"})
	if err != nil {
		pr.Error(err)
		return hosterr.Code(err)
	}
	cfg, err := config.Load()
	if err != nil {
		pr.Error(err)
		return hosterr.Code(err)
	}
	if v, ok := flags["adapter"]; ok {
		cfg.Adapter = v
	}
	if flags["read-only"] == "true" {
		cfg.ReadOnly = true
	}
	if flags["version"] == "true" || (len(words) == 1 && words[0] == "version") {
		fmt.Fprintf(a.Stdout, "hostops %s\n", Version)
		return 0
	}
	if len(words) == 0 || words[0] == "help" || flags["help"] == "true" || flags["h"] == "true" {
		topic := words
		if len(topic) > 0 && topic[0] == "help" {
			topic = topic[1:]
		}
		a.help(topic, cfg.ReadOnly)
		return 0
	}

	cmd, pos := match(words)
	if cmd == nil {
		pr.Error(hosterr.New(hosterr.Validation, "unknown command %q (see: hostops help)", validate.Printable(strings.Join(words, " "))))
		return hosterr.Validation
	}
	for k := range flags {
		if _, g := globalFlags[k]; !g {
			if _, ok := cmd.Flags[k]; !ok {
				pr.Error(hosterr.New(hosterr.Validation, "flag --%s is not valid for %q", k, cmd.Path))
				return hosterr.Validation
			}
		}
	}
	if cmd.Write && cfg.ReadOnly {
		pr.Error(hosterr.New(hosterr.Permission, "%q is a write command and hostops is in read-only mode", cmd.Path))
		return hosterr.Permission
	}
	switch cfg.Adapter {
	case "openlitespeed", "cyberpanel", "nginx":
	default:
		pr.Error(hosterr.New(hosterr.Validation, "unknown adapter %q", validate.Printable(cfg.Adapter)))
		return hosterr.Validation
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}
	var runner exec.Runner = &exec.OSRunner{ReadOnly: cfg.ReadOnly, Sudo: cfg.UseSudo}
	var prober adapters.Prober = certs.TLSProber{}
	if cfg.Fixtures != "" {
		fr := exec.NewFixtureRunner(cfg.Fixtures, cfg.ReadOnly)
		runner = fr
		prober = certs.FixtureProber{Dir: cfg.Fixtures, Mutated: fr.Mutated}
		// A frozen clock keeps committed fixtures (cert expiry, backup age)
		// meaningful forever. Only honoured in fixture mode.
		for _, k := range []string{"HOSTOPS_NOW", "EVAL_HOSTOPS_NOW"} {
			if v := os.Getenv(k); v != "" {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					now = func() time.Time { return t }
					break
				}
			}
		}
	}
	env := adapters.Env{Run: runner, Cfg: cfg, Probe: prober, Now: now}
	c := &Ctx{Context: context.Background(), App: a, Cmd: cmd, Pos: pos, Flags: flags, Env: env, Out: pr, Cfg: cfg}
	switch cfg.Adapter {
	case "nginx":
		c.Web = &nginx.Adapter{Env: env}
		c.Panel = &backups.Generic{Env: env}
	case "openlitespeed":
		c.Web = &openlitespeed.Adapter{Env: env}
		c.Panel = &backups.Generic{Env: env}
	default:
		c.Web = &openlitespeed.Adapter{Env: env}
		c.Panel = &cyberpanel.Panel{Env: env}
	}
	if cmd.Write {
		c.dryRun = c.Has("dry-run")
		c.confirm = flags["confirm"]
	}

	log := &audit.Log{Path: auditPath(cfg)}
	if cmd.Write && !c.dryRun {
		// Fail closed: never change a host we cannot record changing.
		if err := probeWritable(log.Path); err != nil {
			pr.Error(hosterr.Wrap(hosterr.Permission, err, "audit log not writable, refusing write command"))
			return hosterr.Permission
		}
	}

	res, runErr := cmd.Run(c)
	code := hosterr.Code(runErr)
	if res != nil && code != hosterr.Confirm {
		c.result = output.Marshal(res)
		if err := pr.Result(res); err != nil && runErr == nil {
			runErr, code = err, hosterr.General
		}
	}
	if runErr != nil && code != hosterr.Confirm {
		pr.Error(runErr)
	}
	_, aerr := log.Append(audit.Entry{
		Actor: audit.CurrentActor(), Command: cmd.Path, Argv: args, Mode: runner.Mode(),
		DryRun: c.dryRun, ConfirmToken: c.confirm, ExitCode: code, ResultSHA256: audit.Hash(c.result),
	})
	if aerr != nil {
		pr.Diag("hostops: warning: audit log append failed: %v", aerr)
		if cmd.Write && !c.dryRun && code == 0 {
			return hosterr.Partial
		}
	}
	return code
}

func auditPath(cfg config.Config) string {
	if cfg.AuditLog != "" {
		return cfg.AuditLog
	}
	return audit.DefaultPath()
}

func probeWritable(p string) error {
	if err := os.MkdirAll(dirOf(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

// match finds the longest command path that prefixes words.
func match(words []string) (*Command, []string) {
	var best *Command
	bestN := 0
	for _, c := range registry() {
		parts := strings.Fields(c.Path)
		if len(parts) > len(words) || len(parts) <= bestN {
			continue
		}
		ok := true
		for i, p := range parts {
			if words[i] != p {
				ok = false
				break
			}
		}
		if ok {
			best, bestN = c, len(parts)
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, words[bestN:]
}

// invocation reconstructs the canonical command line for next_step hints.
func (c *Ctx) invocation() string {
	parts := []string{"hostops", c.Cmd.Path}
	parts = append(parts, c.Pos...)
	keys := make([]string, 0, len(c.Flags))
	for k := range c.Flags {
		if k == "dry-run" || k == "confirm" || k == "json" || k == "plain" || k == "q" || k == "quiet" || k == "no-color" || k == "no-input" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if c.Flags[k] == "true" {
			parts = append(parts, "--"+k)
		} else {
			parts = append(parts, "--"+k+"="+c.Flags[k])
		}
	}
	return strings.Join(parts, " ")
}

// gate implements the dry-run / confirm protocol for a write command. It
// returns (dryRunResult, nil) for --dry-run, an exit-4 error when the token
// is missing or wrong, and (nil, nil) when execution may proceed.
func (c *Ctx) gate(p confirm.Plan) (any, error) {
	now := c.Env.Now()
	if c.dryRun {
		d := confirm.NewDryRun(p, c.invocation(), now)
		c.token = d.ConfirmToken
		return d, nil
	}
	valid := confirm.Check(p, c.confirm, now)
	if valid {
		used, err := audit.TokenUsed(auditPath(c.Cfg), c.confirm)
		if err != nil {
			return nil, hosterr.Wrap(hosterr.Permission, err, "cannot read audit log to check token reuse")
		}
		if used {
			env := confirm.NewEnvelope(p, c.confirm, c.invocation())
			env.Reason = "token_already_used"
			c.result = output.Marshal(env)
			c.Out.Envelope(env)
			return nil, confirm.ErrRequired(env.Reason)
		}
	}
	if !valid {
		env := confirm.NewEnvelope(p, c.confirm, c.invocation())
		c.result = output.Marshal(env)
		c.Out.Envelope(env)
		return nil, confirm.ErrRequired(env.Reason)
	}
	return nil, nil
}

// positional returns exactly n positionals or a usage error.
func (c *Ctx) positional(n int) error {
	if len(c.Pos) != n {
		return hosterr.New(hosterr.Validation, "usage: hostops %s %s", c.Cmd.Path, c.Cmd.Args)
	}
	return nil
}

func (a *App) help(topic []string, readOnly bool) {
	w := a.Stdout
	prefix := strings.Join(topic, " ")
	fmt.Fprintf(w, "hostops %s — allowlisted, audited server operations.\n\n", Version)
	fmt.Fprintln(w, "Methodology: observe → plan → dry-run → confirm → execute → verify-served → log")
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range registry() {
		if readOnly && c.Write {
			continue
		}
		if prefix != "" && !strings.HasPrefix(c.Path, prefix) {
			continue
		}
		kind := "read "
		if c.Write {
			kind = "WRITE"
		}
		fmt.Fprintf(w, "  %-5s %-28s %s\n", kind, strings.TrimSpace(c.Path+" "+c.Args), c.Summary)
		if prefix != "" {
			keys := make([]string, 0, len(c.Flags))
			for k := range c.Flags {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(w, "          --%-18s %s\n", k, c.Flags[k].help)
			}
		}
	}
	fmt.Fprintln(w, "\nGlobal flags: --json --plain --no-color --no-input -q --adapter=<openlitespeed|cyberpanel|nginx> --read-only")
	if !readOnly {
		fmt.Fprintln(w, "\nWrite commands never act without --confirm=<token>. Run them with --dry-run first;")
		fmt.Fprintln(w, "the plan it prints carries the token. Without a valid token they exit 4.")
	}
	fmt.Fprintln(w, "\nExit codes: 0 ok, 1 general, 2 permission, 3 validation, 4 confirmation required,")
	fmt.Fprintln(w, "            5 verification failed, 6 partial/inconclusive")
}
