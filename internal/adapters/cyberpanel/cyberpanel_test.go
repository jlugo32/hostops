package cyberpanel

import "testing"

func TestBackupSteps(t *testing.T) {
	p := &Panel{}
	c := p.BackupCreateSteps("example.com")[0]
	if c.String() != "cyberpanel createBackup --domainName example.com --backupPath /home/backup" || !c.Mutates {
		t.Fatalf("%s", c)
	}
	// Files in /home/backup are passed by bare name so the CLI takes the GUI path.
	r := p.BackupRestoreSteps("/home/backup/backup-example.com-09.27.2026_03-00-00.tar.gz")[0]
	if r.String() != "cyberpanel restoreBackup --fileName backup-example.com-09.27.2026_03-00-00.tar.gz" {
		t.Fatalf("%s", r)
	}
	r = p.BackupRestoreSteps("/home/example.com/backup/backup-example.com-09.27.2026_03-00-00.tar.gz")[0]
	if r.String() != "cyberpanel restoreBackup --fileName /home/example.com/backup/backup-example.com-09.27.2026_03-00-00.tar.gz" {
		t.Fatalf("%s", r)
	}
	if p.BackupCreateSteps("example.com;id")[0].Validate() == nil {
		t.Fatal("injection accepted")
	}
}
