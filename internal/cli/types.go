package cli

import (
	"fmt"
	"strings"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/adapters/backups"
	"github.com/jlugo32/hostops/internal/adapters/certs"
	"github.com/jlugo32/hostops/internal/adapters/fail2ban"
	"github.com/jlugo32/hostops/internal/adapters/firewalld"
	"github.com/jlugo32/hostops/internal/adapters/mariadb"
	"github.com/jlugo32/hostops/internal/adapters/systemd"
)

// Every JSON document carries "schema"; docs/schema/<name>.v1.json is
// generated from these types (see schema_test.go).

type SitesList struct {
	Schema  string          `json:"schema"`
	Adapter string          `json:"adapter"`
	Sites   []adapters.Site `json:"sites"`
}

func (s SitesList) Table() ([]string, [][]string) {
	var rows [][]string
	for _, x := range s.Sites {
		rows = append(rows, []string{x.Domain, x.DocRoot, x.PHP, fmt.Sprint(len(x.Problems))})
	}
	return []string{"DOMAIN", "DOCROOT", "PHP", "PROBLEMS"}, rows
}

type SiteGet struct {
	Schema string        `json:"schema"`
	Site   adapters.Site `json:"site"`
	Cert   *certs.Info   `json:"cert"`
}

type SiteCheck struct {
	Domain       string   `json:"domain"`
	OK           bool     `json:"ok"`
	CertDaysLeft *int     `json:"cert_days_left"`
	Problems     []string `json:"problems"`
}

type SitesCheck struct {
	Schema string      `json:"schema"`
	OK     bool        `json:"ok"`
	Sites  []SiteCheck `json:"sites"`
}

func (s SitesCheck) Table() ([]string, [][]string) {
	var rows [][]string
	for _, x := range s.Sites {
		d := "-"
		if x.CertDaysLeft != nil {
			d = fmt.Sprint(*x.CertDaysLeft)
		}
		rows = append(rows, []string{x.Domain, map[bool]string{true: "ok", false: "PROBLEM"}[x.OK], d, strings.Join(x.Problems, "; ")})
	}
	return []string{"DOMAIN", "STATUS", "CERT_DAYS", "PROBLEMS"}, rows
}

type CertEntry struct {
	Domain            string      `json:"domain"`
	Disk              *certs.Info `json:"disk"`
	Served            *certs.Info `json:"served,omitempty"`
	ServedMatchesDisk *bool       `json:"served_matches_disk,omitempty"`
	Error             string      `json:"error,omitempty"`
	ServedError       string      `json:"served_error,omitempty"`
}

type CertStatus struct {
	Schema string      `json:"schema"`
	Certs  []CertEntry `json:"certs"`
}

func (s CertStatus) Table() ([]string, [][]string) {
	var rows [][]string
	for _, c := range s.Certs {
		if c.Disk == nil {
			rows = append(rows, []string{c.Domain, "-", "-", "-", c.Error})
			continue
		}
		st := ""
		if c.Disk.Staging {
			st = "STAGING"
		}
		rows = append(rows, []string{c.Domain, fmt.Sprint(c.Disk.DaysLeft), c.Disk.NotAfter[:10], c.Disk.Issuer, st})
	}
	return []string{"DOMAIN", "DAYS", "EXPIRES", "ISSUER", "FLAGS"}, rows
}

type ServiceStatus struct {
	Schema string `json:"schema"`
	systemd.Status
}

type Firewall struct {
	Schema  string           `json:"schema"`
	Running bool             `json:"running"`
	Zones   []firewalld.Zone `json:"zones"`
}

type Fail2ban struct {
	Schema            string          `json:"schema"`
	Jails             []fail2ban.Jail `json:"jails"`
	SessionIP         string          `json:"session_ip,omitempty"`
	SessionIPBannedIn []string        `json:"session_ip_banned_in,omitempty"`
}

func (f Fail2ban) Table() ([]string, [][]string) {
	var rows [][]string
	for _, j := range f.Jails {
		rows = append(rows, []string{j.Name, fmt.Sprint(j.CurrentlyFailed), fmt.Sprint(j.CurrentlyBanned), strings.Join(j.BannedIPs, " ")})
	}
	return []string{"JAIL", "FAILED", "BANNED", "IPS"}, rows
}

type BackupList struct {
	Schema  string           `json:"schema"`
	Backups []backups.Backup `json:"backups"`
}

func (b BackupList) Table() ([]string, [][]string) {
	var rows [][]string
	for _, x := range b.Backups {
		rows = append(rows, []string{x.Path, x.Domain, fmt.Sprintf("%.1f", x.AgeHours), fmt.Sprint(x.GUIVisible)})
	}
	return []string{"PATH", "DOMAIN", "AGE_H", "GUI"}, rows
}

type DBList struct {
	Schema    string   `json:"schema"`
	Databases []string `json:"databases"`
}

type DBSize struct {
	Schema  string         `json:"schema"`
	Schemas []mariadb.Size `json:"schemas"`
}

type DBSlowlog struct {
	Schema   string              `json:"schema"`
	Settings mariadb.SlowVars    `json:"settings"`
	Queries  []mariadb.SlowQuery `json:"queries"`
	Note     string              `json:"note,omitempty"`
}

type Journal struct {
	Schema  string                 `json:"schema"`
	Unit    string                 `json:"unit,omitempty"`
	Entries []systemd.JournalEntry `json:"entries"`
}

type StepResult struct {
	ID       string   `json:"id"`
	Argv     []string `json:"argv"`
	ExitCode int      `json:"exit_code"`
	Error    string   `json:"error,omitempty"`
}

type VerifyItem struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type WriteResult struct {
	Schema       string       `json:"schema"`
	Command      string       `json:"command"`
	Target       string       `json:"target"`
	OK           bool         `json:"ok"`
	Steps        []StepResult `json:"steps"`
	Verification []VerifyItem `json:"verification"`
	Note         string       `json:"note,omitempty"`
}

func (w *WriteResult) Table() ([]string, [][]string) {
	var rows [][]string
	for _, s := range w.Steps {
		rows = append(rows, []string{"step", s.ID, fmt.Sprint(s.ExitCode), strings.Join(s.Argv, " ")})
	}
	for _, v := range w.Verification {
		rows = append(rows, []string{"verify", v.Check, map[bool]string{true: "ok", false: "FAIL"}[v.OK], v.Detail})
	}
	if w.Note != "" {
		rows = append(rows, []string{"note", "", "", w.Note})
	}
	return []string{"KIND", "ID", "RESULT", "DETAIL"}, rows
}
