// Package cyberpanel adds CyberPanel's backup CLI on top of the
// OpenLiteSpeed web-server adapter.
package cyberpanel

import (
	"path/filepath"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/exec"
)

// Panel implements adapters.Panel with the cyberpanel CLI.
type Panel struct{ Env adapters.Env }

func (p *Panel) Name() string { return "cyberpanel" }

// BackupCreateSteps writes straight into /home/backup so the GUI restore
// page can see the file. The CLI's default (/home/<domain>/backup) cannot.
// Note: the CLI prints "0" and exits 0 on failure, so callers must verify
// that a new file appeared rather than trusting the exit code.
func (p *Panel) BackupCreateSteps(domain string) []exec.Command {
	return []exec.Command{{ID: "cyberpanel.backup.create", Bin: exec.Cyberpanel, Mutates: true, Timeout: 60 * time.Minute, Args: []exec.Arg{
		exec.Lit("createBackup"), exec.Lit("--domainName"), exec.Param(domain), exec.Lit("--backupPath"), exec.Lit(backups.GUIDir)}}}
}

// BackupRestoreSteps passes a bare file name for files in /home/backup (the
// CLI then takes the GUI restore path) and a full path otherwise.
func (p *Panel) BackupRestoreSteps(file string) []exec.Command {
	arg := file
	if filepath.Dir(file) == backups.GUIDir {
		arg = filepath.Base(file)
	}
	return []exec.Command{{ID: "cyberpanel.backup.restore", Bin: exec.Cyberpanel, Mutates: true, Timeout: 60 * time.Minute, Args: []exec.Arg{
		exec.Lit("restoreBackup"), exec.Lit("--fileName"), exec.Param(arg)}}}
}

func (p *Panel) BackupDirs(domain string) []string {
	return []string{backups.GUIDir, filepath.Join(p.Env.Cfg.HomeRoot, domain, "backup")}
}
