// Package nginx reads nginx server blocks and builds test+reload commands.
// It is the second web-server target (Ubuntu/Debian layouts).
package nginx

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/exec"
)

// Adapter implements adapters.WebServer for nginx.
type Adapter struct{ Env adapters.Env }

func (a *Adapter) Name() string { return "nginx" }
func (a *Adapter) Unit() string { return "nginx" }

// TestCmd is `nginx -t`; reload is refused unless it passes.
func TestCmd() exec.Command {
	return exec.Command{ID: "nginx.test", Bin: exec.Nginx, Args: []exec.Arg{exec.Lit("-t"), exec.Lit("-q")}}
}

// ReloadSteps validates config first, then reloads.
func (a *Adapter) ReloadSteps() []exec.Command {
	return []exec.Command{TestCmd(), {ID: "nginx.reload", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("reload"), exec.Lit("nginx")}, Mutates: true}}
}

type block struct {
	directives map[string][]string
	file       string
}

// tokenize splits nginx config into tokens, dropping comments and honouring quotes.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			flush()
		case c == '{' || c == '}' || c == ';':
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

// serverBlocks returns the top-level directives of each server{} in text.
func serverBlocks(text, file string) []block {
	toks := tokenize(text)
	var out []block
	depth, serverDepth := 0, -1
	var stmt []string
	var cur *block
	for _, t := range toks {
		switch t {
		case "{":
			if len(stmt) > 0 && stmt[0] == "server" && serverDepth < 0 {
				serverDepth = depth
				out = append(out, block{directives: map[string][]string{}, file: file})
				cur = &out[len(out)-1]
			}
			depth++
			stmt = nil
		case "}":
			depth--
			if depth == serverDepth {
				serverDepth, cur = -1, nil
			}
			stmt = nil
		case ";":
			if cur != nil && depth == serverDepth+1 && len(stmt) > 0 {
				cur.directives[stmt[0]] = append(cur.directives[stmt[0]], strings.Join(stmt[1:], " "))
			}
			stmt = nil
		default:
			stmt = append(stmt, t)
		}
	}
	return out
}

// Sites reads sites-enabled/* and conf.d/*.conf.
func (a *Adapter) Sites(_ context.Context) ([]adapters.Site, error) {
	root := a.Env.Cfg.NginxRoot
	var files []string
	for _, g := range []string{"sites-enabled/*", "conf.d/*.conf"} {
		m, _ := filepath.Glob(a.Env.Path(filepath.Join(root, g)))
		files = append(files, m...)
	}
	sort.Strings(files)
	seen := map[string]*adapters.Site{}
	var order []string
	for _, f := range files {
		b, err := a.Env.ReadFile(strings.TrimPrefix(f, strings.TrimSuffix(a.Env.Path("/"), "/")))
		if err != nil {
			continue
		}
		hostPath := strings.TrimPrefix(f, strings.TrimSuffix(a.Env.Path("/"), "/"))
		for _, blk := range serverBlocks(string(b), hostPath) {
			names := strings.Fields(strings.Join(blk.directives["server_name"], " "))
			if len(names) == 0 || names[0] == "_" {
				continue
			}
			d := names[0]
			s, ok := seen[d]
			if !ok {
				s = &adapters.Site{Domain: d, Config: hostPath, Aliases: names[1:], Listeners: []string{}, Problems: []string{}}
				seen[d] = s
				order = append(order, d)
			}
			s.Listeners = append(s.Listeners, blk.directives["listen"]...)
			if r := blk.directives["root"]; len(r) > 0 {
				s.DocRoot = r[0]
			}
			if c := blk.directives["ssl_certificate"]; len(c) > 0 {
				s.CertFile = c[0]
			}
			if k := blk.directives["ssl_certificate_key"]; len(k) > 0 {
				s.KeyFile = k[0]
			}
			if al := blk.directives["access_log"]; len(al) > 0 && al[0] != "off" {
				s.AccessLog = strings.Fields(al[0])[0]
			}
		}
	}
	var out []adapters.Site
	for _, d := range order {
		s := seen[d]
		if s.DocRoot != "" {
			if st, err := a.Env.Stat(s.DocRoot); err != nil || !st.IsDir() {
				s.Problems = append(s.Problems, "root does not exist: "+s.DocRoot)
			}
		}
		if s.CertFile != "" {
			if _, err := a.Env.Stat(s.CertFile); err != nil {
				s.Problems = append(s.Problems, "ssl_certificate missing: "+s.CertFile)
			}
		}
		sort.Strings(s.Listeners)
		out = append(out, *s)
	}
	return out, nil
}
