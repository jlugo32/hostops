package certs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/testhost"
)

var now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func write(t *testing.T, p string, b []byte) {
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStatusAndStaging(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Root = root
	env := adapters.Env{Run: exec.NewFixtureRunner(root, false), Cfg: cfg, Now: func() time.Time { return now }}
	prod, _, _ := testhost.MakeCert(testhost.CertSpec{Domains: []string{"a.example", "www.a.example"}, IssuerCN: "R11", IssuerOrg: "Let's Encrypt", NotBefore: now.AddDate(0, 0, -85), NotAfter: now.AddDate(0, 0, 5), Serial: 1})
	stg, _, _ := testhost.MakeCert(testhost.CertSpec{Domains: []string{"b.example"}, IssuerCN: "(STAGING) Ersatz Edamame E1", IssuerOrg: "(STAGING) Let's Encrypt", NotBefore: now, NotAfter: now.AddDate(0, 0, 90), Serial: 2})
	write(t, filepath.Join(root, "etc/letsencrypt/live/a.example/fullchain.pem"), prod)
	write(t, filepath.Join(root, "root/.acme.sh/b.example_ecc/fullchain.cer"), stg)

	a, _, err := OnDisk(env, "a.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.DaysLeft != 5 || a.Staging || !a.CoversName || a.Issuer != "Let's Encrypt / R11" {
		t.Fatalf("%+v", a)
	}
	b, _, err := OnDisk(env, "b.example", "")
	if err != nil || !b.Staging {
		t.Fatalf("staging not flagged: %+v %v", b, err)
	}
	if _, _, err := OnDisk(env, "none.example", ""); !os.IsNotExist(err) {
		t.Fatalf("missing cert: %v", err)
	}
}

func TestRenewCmdForcesProduction(t *testing.T) {
	c := RenewCmd(Issuer{Client: "acme.sh", ECC: true}, "a.example")
	if c.String() != "acme.sh --renew -d a.example --force --server letsencrypt --ecc" || !c.Mutates {
		t.Fatalf("%s", c)
	}
	c = RenewCmd(Issuer{Client: "certbot"}, "a.example")
	if !c.Mutates || c.Validate() != nil {
		t.Fatalf("%s", c)
	}
	if RenewCmd(Issuer{Client: "acme.sh"}, "a.example;id").Validate() == nil {
		t.Fatal("injection accepted")
	}
}

func TestFixtureProberSwitchesAfterMutation(t *testing.T) {
	dir := t.TempDir()
	old, _, _ := testhost.MakeCert(testhost.CertSpec{Domains: []string{"a.example"}, IssuerCN: "R11", IssuerOrg: "Let's Encrypt", NotBefore: now, NotAfter: now.AddDate(0, 0, 3), Serial: 1})
	nw, _, _ := testhost.MakeCert(testhost.CertSpec{Domains: []string{"a.example"}, IssuerCN: "R11", IssuerOrg: "Let's Encrypt", NotBefore: now, NotAfter: now.AddDate(0, 0, 90), Serial: 2})
	write(t, filepath.Join(dir, "served/a.example.pem"), old)
	write(t, filepath.Join(dir, "served/a.example.after.pem"), nw)
	mut := false
	p := FixtureProber{Dir: dir, Mutated: func() bool { return mut }}
	c1, _ := p.ServedCert(context.Background(), "a.example")
	mut = true
	c2, _ := p.ServedCert(context.Background(), "a.example")
	if c1.SerialNumber.Int64() != 1 || c2.SerialNumber.Int64() != 2 {
		t.Fatal("prober did not switch")
	}
}

func TestLive_TLSProberLocalhost(t *testing.T) {
	if os.Getenv("HOSTOPS_LIVE") != "1" {
		t.Skip("HOSTOPS_LIVE!=1: needs a real web server on 127.0.0.1:443")
	}
	d := os.Getenv("HOSTOPS_LIVE_DOMAIN")
	if d == "" {
		t.Skip("set HOSTOPS_LIVE_DOMAIN")
	}
	if _, err := (TLSProber{}).ServedCert(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}
