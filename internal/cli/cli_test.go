package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jlugo32/hostops/internal/schema"
)

var hosts, _ = filepath.Abs("../../testdata/hosts")

type run struct {
	code           int
	stdout, stderr string
}

func invoke(t *testing.T, host string, args ...string) run {
	t.Helper()
	work := t.TempDir()
	t.Setenv("HOSTOPS_FIXTURES", filepath.Join(hosts, host))
	t.Setenv("HOSTOPS_NOW", "2026-09-27T12:00:00Z")
	t.Setenv("HOSTOPS_AUDIT_LOG", filepath.Join(work, "audit.jsonl"))
	t.Setenv("HOSTOPS_SYSTEM_CONFIG", filepath.Join(work, "none.toml"))
	t.Setenv("XDG_CONFIG_HOME", work)
	t.Setenv("HOSTOPS_ADAPTER", "")
	t.Setenv("HOSTOPS_READ_ONLY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")
	var o, e bytes.Buffer
	code := (&App{Stdout: &o, Stderr: &e}).Run(args)
	return run{code, o.String(), e.String()}
}

// goldenCases cover every published schema at least once.
var goldenCases = []struct {
	name, host string
	args       []string
	stream     string // "stdout" or "stderr"
	code       int
}{
	{"sites", "base", []string{"sites", "list"}, "stdout", 0},
	{"site", "base", []string{"sites", "get", "example.com"}, "stdout", 0},
	{"sites-check", "ols-vhost-typo", []string{"sites", "check"}, "stdout", 5},
	{"cert-status", "staging-cert", []string{"cert", "status", "--served"}, "stdout", 0},
	{"service-status", "oom-lsphp", []string{"service", "status", "lsws"}, "stdout", 0},
	{"firewall", "base", []string{"firewall", "list"}, "stdout", 0},
	{"fail2ban", "fail2ban-self-lockout", []string{"fail2ban", "status"}, "stdout", 0},
	{"baseline", "hardening-review", []string{"baseline", "check"}, "stdout", 5},
	{"backups", "full-disk", []string{"backup", "list"}, "stdout", 0},
	{"backup-verify", "stale-backup-path", []string{"backup", "verify", "/home/shop.example.net/backup/backup-shop.example.net-09.26.2026_03-00-00.tar.gz", "--gui-compatible"}, "stdout", 5},
	{"db-list", "base", []string{"db", "list"}, "stdout", 0},
	{"db-size", "base", []string{"db", "size"}, "stdout", 0},
	{"db-slowlog", "mariadb-slow-query", []string{"db", "slowlog", "--top", "3"}, "stdout", 0},
	{"logs-top", "bot-flood", []string{"logs", "top", "example.com", "--top", "3"}, "stdout", 0},
	{"journal", "oom-lsphp", []string{"logs", "journal", "--unit", "lsws", "--lines", "50"}, "stdout", 0},
	{"audit-verify", "base", []string{"audit", "verify"}, "stdout", 0},
	{"plan", "expired-cert", []string{"cert", "renew", "shop.example.net", "--dry-run"}, "stdout", 0},
	{"confirm", "expired-cert", []string{"cert", "renew", "shop.example.net"}, "stderr", 4},
	{"error", "base", []string{"sites", "get", "nosuch.example"}, "stderr", 3},
}

var tmpRE = regexp.MustCompile(`"path": "[^"]*audit\.jsonl"`)

func TestGoldenAndSchemas(t *testing.T) {
	covered := map[string]bool{}
	for _, gc := range goldenCases {
		t.Run(gc.name, func(t *testing.T) {
			r := invoke(t, gc.host, gc.args...)
			if r.code != gc.code {
				t.Fatalf("exit %d, want %d\nstdout=%s\nstderr=%s", r.code, gc.code, r.stdout, r.stderr)
			}
			got := r.stdout
			if gc.stream == "stderr" {
				got = r.stderr
			}
			got = tmpRE.ReplaceAllString(got, `"path": "$$HOSTOPS_AUDIT_LOG"`)
			var doc map[string]any
			if err := json.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, got)
			}
			id := strings.TrimPrefix(doc["schema"].(string), "hostops.")
			typ, ok := SchemaTypes[id]
			if !ok {
				t.Fatalf("output schema %q has no entry in SchemaTypes", id)
			}
			covered[id] = true
			sc := roundTrip(schema.Generate(id, id, typ))
			if err := schema.Validate(sc, doc, "$"); err != nil {
				t.Fatalf("output does not match docs/schema/%s.json: %v", id, err)
			}
			golden := filepath.Join("testdata", "golden", gc.name+".json")
			if os.Getenv("HOSTOPS_UPDATE_GOLDEN") == "1" {
				os.MkdirAll(filepath.Dir(golden), 0o755)
				os.WriteFile(golden, []byte(got), 0o644)
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden (run make golden): %v", err)
			}
			if got != string(want) {
				t.Errorf("output differs from %s (run make golden if intended)\n--- got\n%s", golden, got)
			}
		})
	}
	var missing []string
	for id := range SchemaTypes {
		if id != "result.v1" && !covered[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("schemas without a golden case: %v", missing)
	}
}

// roundTrip converts a generated schema to the decoded-JSON shape Validate
// expects ([]string -> []any etc).
func roundTrip(d schema.Doc) schema.Doc {
	b, _ := json.Marshal(d)
	var out map[string]any
	json.Unmarshal(b, &out)
	return fix(out).(map[string]any)
}

func fix(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if k == "required" {
				var ss []string
				for _, s := range y.([]any) {
					ss = append(ss, s.(string))
				}
				x[k] = ss
				continue
			}
			x[k] = fix(y)
		}
		return x
	case []any:
		for i := range x {
			x[i] = fix(x[i])
		}
	}
	return v
}

// TestSchemaFilesUpToDate regenerates docs/schema and fails on drift.
func TestSchemaFilesUpToDate(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "schema")
	for id, typ := range SchemaTypes {
		b, _ := json.MarshalIndent(schema.Generate(id, "hostops "+id+" output", typ), "", "  ")
		b = append(b, '\n')
		p := filepath.Join(dir, id+".json")
		if os.Getenv("HOSTOPS_UPDATE_GOLDEN") == "1" {
			os.MkdirAll(dir, 0o755)
			os.WriteFile(p, b, 0o644)
		}
		have, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(have, b) {
			t.Errorf("%s is stale (run make golden)", p)
		}
	}
}

func TestWriteResultMatchesSchema(t *testing.T) {
	r := invoke(t, "restart-webserver", "sites", "reload", "--dry-run")
	var d struct {
		Token string `json:"confirm_token"`
	}
	json.Unmarshal([]byte(r.stdout), &d)
	// Same audit dir is needed for the token-reuse check, so reuse env.
	var o, e bytes.Buffer
	code := (&App{Stdout: &o, Stderr: &e}).Run([]string{"sites", "reload", "--confirm=" + d.Token})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	var doc map[string]any
	json.Unmarshal(o.Bytes(), &doc)
	if err := schema.Validate(roundTrip(schema.Generate("result.v1", "", SchemaTypes["result.v1"])), doc, "$"); err != nil {
		t.Fatal(err)
	}
}

// Newlines and control characters in argv (which txtar cannot express) must
// fail closed and must not forge audit records.
func TestArgvNewlineInjection(t *testing.T) {
	for _, args := range [][]string{
		{"service", "status", "lsws.service\nExecStart=/bin/sh"},
		{"sites", "get", "x.example\n{\"ts\":\"forged\",\"command\":\"fake\"}"},
		{"fail2ban", "unban", "1.2.3.4\r\n"},
		{"cert", "status", "example.com\x1b[2J"},
	} {
		r := invoke(t, "base", args...)
		if r.code != 3 {
			t.Errorf("%q: exit %d, want 3", args, r.code)
		}
		if strings.Contains(r.stderr, "\x1b") {
			t.Errorf("%q: raw escape echoed to stderr", args)
		}
		log, _ := os.ReadFile(os.Getenv("HOSTOPS_AUDIT_LOG"))
		if n := bytes.Count(log, []byte("\n")); n != 1 {
			t.Errorf("%q: audit log has %d lines, want 1", args, n)
		}
		if bytes.Contains(log, []byte("\n{\"ts\":\"forged\"")) {
			t.Errorf("%q: forged record", args)
		}
	}
}
