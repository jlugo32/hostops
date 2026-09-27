package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrecedence(t *testing.T) {
	d := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", d)
	os.MkdirAll(filepath.Join(d, "hostops"), 0o700)
	os.WriteFile(filepath.Join(d, "hostops", "config.toml"), []byte("adapter = \"nginx\"\nhome_root = \"/srv\"\n"), 0o600)
	sys := filepath.Join(d, "sys.toml")
	os.WriteFile(sys, []byte("adapter = \"openlitespeed\"\n"), 0o600)
	t.Setenv("HOSTOPS_SYSTEM_CONFIG", sys)
	t.Setenv("HOSTOPS_ADAPTER", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Adapter != "openlitespeed" || c.HomeRoot != "/srv" {
		t.Fatalf("system file must beat XDG: %+v", c)
	}
	t.Setenv("HOSTOPS_ADAPTER", "cyberpanel")
	c, _ = Load()
	if c.Adapter != "cyberpanel" {
		t.Fatal("env must beat files")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	d := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", d)
	sys := filepath.Join(d, "sys.toml")
	os.WriteFile(sys, []byte("db_password = \"x\"\n"), 0o600)
	t.Setenv("HOSTOPS_SYSTEM_CONFIG", sys)
	if _, err := Load(); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestFixturesSetRoot(t *testing.T) {
	t.Setenv("HOSTOPS_SYSTEM_CONFIG", filepath.Join(t.TempDir(), "none"))
	t.Setenv("HOSTOPS_FIXTURES", "/fx")
	t.Setenv("HOSTOPS_ROOT", "")
	c, _ := Load()
	if c.Root != "/fx/root" || c.Path("/home") != "/fx/root/home" {
		t.Fatalf("%+v", c)
	}
}
