// Package adapters defines the boundary between the panel-agnostic core and
// host-specific code (ADR-0006). The core only knows Site, WebServer and
// Panel; everything that knows about OpenLiteSpeed, nginx or CyberPanel file
// layouts lives in a sub-package.
package adapters

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/exec"
)

// Env is what every adapter receives: a runner (live or fixture), the
// resolved config, a TLS prober and a clock.
type Env struct {
	Run   exec.Runner
	Cfg   config.Config
	Probe Prober
	Now   func() time.Time
}

// Prober fetches the certificate a server actually presents for a name.
type Prober interface {
	ServedCert(ctx context.Context, domain string) (*x509.Certificate, error)
}

// mutationAware is implemented by the fixture runner.
type mutationAware interface{ Mutated() bool }

// Path maps a host path onto the configured root.
func (e Env) Path(p string) string { return e.Cfg.Path(p) }

// ReadFile reads a host file. In fixture mode, once a mutating command has
// run, "<path>.after" (if present) models the file's new state.
func (e Env) ReadFile(p string) ([]byte, error) {
	real := e.Path(p)
	if m, ok := e.Run.(mutationAware); ok && m.Mutated() {
		if b, err := os.ReadFile(real + ".after"); err == nil {
			return b, nil
		}
	}
	return os.ReadFile(real)
}

// Stat stats a host path.
func (e Env) Stat(p string) (os.FileInfo, error) { return os.Stat(e.Path(p)) }

// fixtureMeta holds what git cannot store for a fixture tree: modification
// times and permission bits. <fixtures>/meta.json maps host paths to values.
type fixtureMeta struct {
	MTimes map[string]string `json:"mtimes"`
	Modes  map[string]string `json:"modes"`
}

var metaCache sync.Map // fixture dir -> *fixtureMeta

func (e Env) meta() *fixtureMeta {
	if e.Cfg.Fixtures == "" {
		return nil
	}
	if m, ok := metaCache.Load(e.Cfg.Fixtures); ok {
		return m.(*fixtureMeta)
	}
	m := &fixtureMeta{}
	if b, err := os.ReadFile(filepath.Join(e.Cfg.Fixtures, "meta.json")); err == nil {
		_ = json.Unmarshal(b, m)
	}
	metaCache.Store(e.Cfg.Fixtures, m)
	return m
}

// ModTime returns a host file's modification time (fixture meta wins).
func (e Env) ModTime(hostPath string, fi os.FileInfo) time.Time {
	if m := e.meta(); m != nil {
		if v, ok := m.MTimes[hostPath]; ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t
			}
		}
	}
	return fi.ModTime()
}

// Perm returns a host file's permission bits (fixture meta wins).
func (e Env) Perm(hostPath string, fi os.FileInfo) os.FileMode {
	if m := e.meta(); m != nil {
		if v, ok := m.Modes[hostPath]; ok {
			if n, err := strconv.ParseUint(v, 8, 32); err == nil {
				return os.FileMode(n)
			}
		}
	}
	return fi.Mode().Perm()
}

// Exec runs c through the configured runner.
func (e Env) Exec(ctx context.Context, c exec.Command) (exec.Result, error) {
	return e.Run.Run(ctx, c)
}

// Site is the panel-agnostic view of one hosted site.
type Site struct {
	Domain    string   `json:"domain"`
	Aliases   []string `json:"aliases"`
	DocRoot   string   `json:"doc_root"`
	Config    string   `json:"config_file"`
	CertFile  string   `json:"cert_file,omitempty"`
	KeyFile   string   `json:"key_file,omitempty"`
	AccessLog string   `json:"access_log,omitempty"`
	PHP       string   `json:"php,omitempty"`
	Listeners []string `json:"listeners"`
	Problems  []string `json:"problems"`
}

// WebServer is implemented by the openlitespeed and nginx adapters.
type WebServer interface {
	Name() string
	Unit() string
	Sites(ctx context.Context) ([]Site, error)
	// ReloadSteps are the commands for a graceful reload, in order.
	ReloadSteps() []exec.Command
}

// Panel is implemented by the cyberpanel adapter; hosts without a panel use
// the generic implementation in the backups package.
type Panel interface {
	Name() string
	BackupCreateSteps(domain string) []exec.Command
	BackupRestoreSteps(file string) []exec.Command
	// BackupDirs are where this panel's backups for domain may live.
	BackupDirs(domain string) []string
}
