package backups

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/testhost"
)

func env(t *testing.T) (adapters.Env, string) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Root = root
	return adapters.Env{Run: exec.NewFixtureRunner(root, false), Cfg: cfg, Now: time.Now}, root
}

func TestVerifyGUICompatible(t *testing.T) {
	e, root := env(t)
	good := "/home/backup/backup-example.com-09.26.2026_03-00-00.tar.gz"
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, good), "example.com", true)
	r, err := Verify(e, good, true)
	if err != nil || !r.OK || r.GUICompatible == nil || !*r.GUICompatible || len(r.Databases) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// Same archive in the CLI default location is not visible to the GUI.
	stale := "/home/example.com/backup/backup-example.com-09.26.2026_03-00-00.tar.gz"
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, stale), "example.com", true)
	r, _ = Verify(e, stale, true)
	if r.OK || *r.GUICompatible {
		t.Fatalf("stale location passed: %+v", r)
	}
	// Without meta.xml.
	nometa := "/home/backup/backup-example.com-09.25.2026_03-00-00.tar.gz"
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, nometa), "example.com", false)
	r, _ = Verify(e, nometa, true)
	if r.OK {
		t.Fatal("missing meta.xml passed")
	}
}

func TestVerifyTruncated(t *testing.T) {
	e, root := env(t)
	p := "/home/backup/backup-example.com-09.26.2026_03-00-00.tar.gz"
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, p), "example.com", true)
	b, _ := os.ReadFile(filepath.Join(root, p))
	os.WriteFile(filepath.Join(root, p), b[:len(b)/2], 0o600)
	r, _ := Verify(e, p, false)
	if r.OK || r.Checks[0].OK {
		t.Fatalf("truncated archive passed: %+v", r)
	}
}

func TestList(t *testing.T) {
	e, root := env(t)
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, "home/backup/backup-a.example-09.26.2026_03-00-00.tar.gz"), "a.example", true)
	testhost.WriteCyberPanelBackup(t, filepath.Join(root, "home/b.example/backup/backup-b.example-01.02.2026_03-00-00.tar.gz"), "b.example", true)
	old := time.Now().Add(-200 * 24 * time.Hour)
	os.Chtimes(filepath.Join(root, "home/b.example/backup/backup-b.example-01.02.2026_03-00-00.tar.gz"), old, old)
	bs, _ := List(e)
	if len(bs) != 2 || !bs[0].GUIVisible || bs[1].GUIVisible || bs[1].Domain != "b.example" || bs[1].AgeHours < 4000 {
		t.Fatalf("%+v", bs)
	}
}

func TestGenericSteps(t *testing.T) {
	e, _ := env(t)
	e.Now = func() time.Time { return time.Date(2026, 9, 27, 14, 5, 0, 0, time.UTC) }
	g := &Generic{Env: e}
	c := g.BackupCreateSteps("example.com")[0]
	if c.String() != "tar --create --gzip --file /var/backups/hostops/example.com-20260927-14.tar.gz --directory /home example.com" || c.Validate() != nil {
		t.Fatal(c.String())
	}
}
