package openlitespeed

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/exec"
)

// knownVhostKeys are top-level vhost.conf directives OLS accepts. A key not in
// this set is almost always a typo that OLS silently ignores.
var knownVhostKeys = map[string]bool{
	"docroot": true, "vhdomain": true, "vhaliases": true, "adminemails": true, "enablegzip": true,
	"enableipgeo": true, "index": true, "errorlog": true, "accesslog": true, "scripthandler": true,
	"extprocessor": true, "phpinioverride": true, "module": true, "rewrite": true, "context": true,
	"vhssl": true, "enablebr": true, "cgroups": true, "setuidmode": true, "errorpage": true,
	"expires": true, "security": true, "realm": true, "websocket": true, "awstats": true,
	"general": true, "hotlinkctrl": true, "accesscontrol": true, "enablescript": true,
	"restrained": true, "allowsymbollink": true, "vhroot": true, "configfile": true,
	"maxkeepalivereq": true, "smartkeepalive": true, "chrootmode": true, "enabledynamicgzipcompress": true,
}

// Adapter reads OLS config under Env.
type Adapter struct {
	Env adapters.Env
}

func (a *Adapter) Name() string { return "openlitespeed" }
func (a *Adapter) Unit() string { return "lsws" }

// ReloadSteps is a graceful restart: OLS's unit maps reload to lswsctrl
// restart, which drains existing connections.
func (a *Adapter) ReloadSteps() []exec.Command {
	return []exec.Command{{ID: "openlitespeed.reload", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("reload"), exec.Lit("lsws")}, Mutates: true}}
}

type vhostDef struct {
	name, vhRoot, configFile string
}

func (a *Adapter) serverConfig() (string, error) {
	return filepath.Join(a.Env.Cfg.OLSRoot, "conf", "httpd_config.conf"), nil
}

// Sites parses httpd_config.conf and every referenced vhost.conf.
func (a *Adapter) Sites(_ context.Context) ([]adapters.Site, error) {
	p, _ := a.serverConfig()
	b, err := a.Env.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	root, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	listeners := map[string][]string{} // vhost -> listener names
	for _, l := range root.All("listener") {
		for _, m := range l.All("map") {
			vh, _ := splitKV(m.Value)
			listeners[vh] = append(listeners[vh], l.Value)
		}
	}
	var defs []vhostDef
	for _, v := range root.All("virtualHost") {
		defs = append(defs, vhostDef{name: v.Value, vhRoot: v.Get("vhRoot"), configFile: v.Get("configFile")})
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].name < defs[j].name })
	var out []adapters.Site
	for _, d := range defs {
		if d.configFile == "" || !strings.Contains(d.name, ".") {
			continue // built-in Example vhost and the like
		}
		out = append(out, a.site(d, listeners[d.name]))
	}
	return out, nil
}

func (a *Adapter) site(d vhostDef, listeners []string) adapters.Site {
	vars := map[string]string{"VH_NAME": d.name, "SERVER_ROOT": a.Env.Cfg.OLSRoot}
	vhRoot := expand(d.vhRoot, vars)
	vars["VH_ROOT"] = strings.TrimSuffix(vhRoot, "/")
	s := adapters.Site{Domain: d.name, Config: expand(d.configFile, vars), Listeners: listeners, Aliases: []string{}, Problems: []string{}}
	if s.Listeners == nil {
		s.Listeners = []string{}
	}
	sort.Strings(s.Listeners)
	if len(listeners) == 0 {
		s.Problems = append(s.Problems, "not mapped on any listener")
	}
	b, err := a.Env.ReadFile(s.Config)
	if err != nil {
		s.Problems = append(s.Problems, "vhost config unreadable: "+s.Config)
		return s
	}
	n, err := Parse(b)
	if err != nil {
		s.Problems = append(s.Problems, "vhost config syntax: "+err.Error())
		return s
	}
	for _, k := range n.Kids {
		if !knownVhostKeys[strings.ToLower(k.Key)] {
			s.Problems = append(s.Problems, fmt.Sprintf("unknown directive %q at line %d (typo? OLS ignores it silently)", k.Key, k.Line))
		}
	}
	doc := n.Get("docRoot")
	if doc == "" {
		s.Problems = append(s.Problems, "no docRoot directive")
	}
	s.DocRoot = expand(doc, vars)
	vars["DOC_ROOT"] = s.DocRoot
	if al := n.Get("vhAliases"); al != "" {
		s.Aliases = append(s.Aliases, strings.FieldsFunc(expand(al, vars), func(r rune) bool { return r == ',' || r == ' ' })...)
	}
	if ssl := n.Find("vhssl"); ssl != nil {
		s.CertFile, s.KeyFile = expand(ssl.Get("certFile"), vars), expand(ssl.Get("keyFile"), vars)
	}
	if al := n.Find("accesslog"); al != nil {
		s.AccessLog = expand(al.Value, vars)
	}
	for _, ep := range n.All("extprocessor") {
		if p := ep.Get("path"); strings.Contains(p, "lsphp") {
			s.PHP = filepath.Base(filepath.Dir(filepath.Dir(p)))
		}
	}
	if s.DocRoot != "" {
		if st, err := a.Env.Stat(s.DocRoot); err != nil || !st.IsDir() {
			s.Problems = append(s.Problems, "docRoot does not exist: "+s.DocRoot)
		}
	}
	if s.CertFile != "" {
		if _, err := a.Env.Stat(s.CertFile); err != nil {
			s.Problems = append(s.Problems, "certFile missing: "+s.CertFile)
		}
	}
	return s
}
