// Package certs inspects TLS certificates on disk and as served, and builds
// renewal commands for acme.sh (CyberPanel's issuer) or certbot.
//
// Two failure modes this package exists to catch, both seen in production:
//   - a renewal "succeeds" but the server keeps serving the old cert because
//     nothing reloaded it, so --verify-served compares what is served with
//     what is on disk;
//   - a Let's Encrypt STAGING cert gets installed, which browsers reject, so
//     staging issuers are always flagged and never count as verified.
package certs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/exec"
)

// Info summarises one certificate.
type Info struct {
	Domain      string   `json:"domain"`
	Source      string   `json:"source"`
	Path        string   `json:"path,omitempty"`
	Subject     string   `json:"subject"`
	Names       []string `json:"names"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	Staging     bool     `json:"staging"`
	CoversName  bool     `json:"covers_domain"`
	Fingerprint string   `json:"sha256"`
}

// Describe builds Info for c.
func Describe(domain, source, path string, c *x509.Certificate, now time.Time) Info {
	fp := sha256.Sum256(c.Raw)
	issuer := c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		issuer = c.Issuer.Organization[0] + " / " + issuer
	}
	return Info{
		Domain: domain, Source: source, Path: path,
		Subject: c.Subject.CommonName, Names: append([]string{}, c.DNSNames...),
		Issuer: issuer, NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:    int(c.NotAfter.Sub(now).Hours() / 24),
		Staging:     IsStaging(c),
		CoversName:  c.VerifyHostname(domain) == nil,
		Fingerprint: hex.EncodeToString(fp[:]),
	}
}

// IsStaging reports whether c was issued by a Let's Encrypt staging CA or
// another obviously non-trusted test issuer.
func IsStaging(c *x509.Certificate) bool {
	s := strings.ToLower(c.Issuer.String())
	for _, m := range []string{"staging", "fake le", "happy hacker", "(test)"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// ParsePEM returns the first certificate (the leaf) in b.
func ParsePEM(b []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("no certificate found")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

// Candidates returns the on-disk paths checked for domain, most specific
// first. vhostCert is the path the web server config names, if known.
func Candidates(cfg adapters.Env, domain, vhostCert string) []string {
	var out []string
	if vhostCert != "" {
		out = append(out, vhostCert)
	}
	out = append(out,
		filepath.Join(cfg.Cfg.LELive, domain, "fullchain.pem"),
		filepath.Join(cfg.Cfg.LELive, domain, "cert.pem"),
		filepath.Join(cfg.Cfg.AcmeHome, domain+"_ecc", "fullchain.cer"),
		filepath.Join(cfg.Cfg.AcmeHome, domain, "fullchain.cer"),
	)
	return out
}

// OnDisk loads the certificate the web server is configured to use.
func OnDisk(env adapters.Env, domain, vhostCert string) (Info, *x509.Certificate, error) {
	for _, p := range Candidates(env, domain, vhostCert) {
		b, err := env.ReadFile(p)
		if err != nil {
			continue
		}
		c, err := ParsePEM(b)
		if err != nil {
			return Info{}, nil, fmt.Errorf("%s: %w", p, err)
		}
		return Describe(domain, "disk", p, c, env.Now()), c, nil
	}
	return Info{}, nil, os.ErrNotExist
}

// Issuer is the ACME client managing a domain.
type Issuer struct {
	Client string // "acme.sh" or "certbot"
	ECC    bool
	Conf   string
	// StagingConfigured is true when the saved renewal config points at a
	// staging directory; renewals then force the production server.
	StagingConfigured bool
}

// FindIssuer looks for acme.sh or certbot renewal config for domain.
func FindIssuer(env adapters.Env, domain string) (Issuer, bool) {
	for _, ecc := range []bool{true, false} {
		dir := domain
		if ecc {
			dir += "_ecc"
		}
		conf := filepath.Join(env.Cfg.AcmeHome, dir, domain+".conf")
		if b, err := env.ReadFile(conf); err == nil {
			return Issuer{Client: "acme.sh", ECC: ecc, Conf: conf, StagingConfigured: strings.Contains(strings.ToLower(string(b)), "staging")}, true
		}
	}
	conf := filepath.Join("/etc/letsencrypt/renewal", domain+".conf")
	if b, err := env.ReadFile(conf); err == nil {
		return Issuer{Client: "certbot", Conf: conf, StagingConfigured: strings.Contains(string(b), "staging")}, true
	}
	return Issuer{}, false
}

// RenewCmd builds the renewal command. acme.sh is always pointed at the
// production Let's Encrypt server so a stale staging config cannot win.
func RenewCmd(is Issuer, domain string) exec.Command {
	if is.Client == "certbot" {
		return exec.Command{ID: "certs.renew.certbot", Bin: exec.Certbot, Mutates: true, Timeout: 5 * time.Minute, Args: []exec.Arg{
			exec.Lit("renew"), exec.Lit("--cert-name"), exec.Param(domain), exec.Lit("--force-renewal"), exec.Lit("--non-interactive"),
			exec.Lit("--server"), exec.Lit("https://acme-v02.api.letsencrypt.org/directory")}}
	}
	args := []exec.Arg{exec.Lit("--renew"), exec.Lit("-d"), exec.Param(domain), exec.Lit("--force"), exec.Lit("--server"), exec.Lit("letsencrypt")}
	if is.ECC {
		args = append(args, exec.Lit("--ecc"))
	}
	return exec.Command{ID: "certs.renew.acme", Bin: exec.AcmeSh, Mutates: true, Timeout: 5 * time.Minute, Args: args}
}

// TLSProber connects to the local web server with SNI and returns the leaf
// it presents. It does not validate the chain: the point is to see exactly
// what is served, including broken or staging certs.
type TLSProber struct {
	Addr    string // default 127.0.0.1:443
	Timeout time.Duration
}

func (p TLSProber) ServedCert(ctx context.Context, domain string) (*x509.Certificate, error) {
	addr := p.Addr
	if addr == "" {
		addr = "127.0.0.1:443"
	}
	to := p.Timeout
	if to == 0 {
		to = 8 * time.Second
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: to}, Config: &tls.Config{ServerName: domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // inspection only, see type doc
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // probe connection, nothing written
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	return st.PeerCertificates[0], nil
}

// FixtureProber serves certs from <dir>/served/<domain>.pem, switching to
// <domain>.after.pem once the runner has executed a mutation.
type FixtureProber struct {
	Dir     string
	Mutated func() bool
}

func (p FixtureProber) ServedCert(_ context.Context, domain string) (*x509.Certificate, error) {
	base := filepath.Join(p.Dir, "served", domain)
	if p.Mutated != nil && p.Mutated() {
		if b, err := os.ReadFile(base + ".after.pem"); err == nil {
			return ParsePEM(b)
		}
	}
	b, err := os.ReadFile(base + ".pem")
	if err != nil {
		return nil, fmt.Errorf("connection refused (fixture has no served cert for %s)", domain)
	}
	return ParsePEM(b)
}
