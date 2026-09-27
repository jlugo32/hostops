// Package backups lists and verifies site backups, and provides the generic
// (panel-less) backup implementation.
//
// "GUI compatible" means CyberPanel's web restore page can see and restore
// the file. From CyberPanel's own source (plogical/backupUtilities.py):
//   - the restore page only lists files in /home/backup/ — the CLI's default
//     output, /home/<domain>/backup/, is invisible to it;
//   - the archive root must hold meta.xml (with <masterDomain>) and
//     public_html.tar.gz;
//   - names are backup-<domain>-MM.DD.YYYY_HH-MM-SS.tar.gz. The restore code
//     calls Python's str.strip(".tar.gz"), which strips a character SET, so a
//     name that does not start with "backup-" can be silently mangled.
package backups

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/exec"
)

// maxUncompressed caps how much verify will decompress.
const maxUncompressed = int64(512) << 30

// GUIDir is where CyberPanel's restore page looks.
const GUIDir = "/home/backup"

var nameRE = regexp.MustCompile(`^backup-(.+)-(\d{2})\.(\d{2})\.(\d{4})_(\d{2})-(\d{2})-(\d{2})\.tar\.gz$`)

// Backup is one backup file.
type Backup struct {
	Path       string  `json:"path"`
	Domain     string  `json:"domain"`
	Bytes      int64   `json:"bytes"`
	Modified   string  `json:"modified"`
	AgeHours   float64 `json:"age_hours"`
	GUIVisible bool    `json:"gui_visible"`
}

// DomainFromName extracts the domain from a CyberPanel-style name.
func DomainFromName(name string) string {
	if m := nameRE.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	if i := strings.Index(name, "-20"); i > 0 { // generic: <domain>-YYYYMMDD-HH.tar.gz
		return name[:i]
	}
	return ""
}

// List finds backups in the GUI dir, each site's backup dir and extraDirs.
func List(env adapters.Env, extraDirs ...string) ([]Backup, error) {
	globs := []string{GUIDir + "/*.tar.gz", env.Cfg.HomeRoot + "/*/backup/*.tar.gz"}
	for _, d := range extraDirs {
		globs = append(globs, d+"/*.tar.gz")
	}
	seen := map[string]bool{}
	var out []Backup
	now := env.Now()
	mutated := false
	if m, ok := env.Run.(interface{ Mutated() bool }); ok {
		mutated = m.Mutated()
	}
	for _, g := range globs {
		m, _ := filepath.Glob(env.Path(g))
		if mutated {
			// Fixture mode: "<name>.tar.gz.after" files appear once a mutation ran.
			extra, _ := filepath.Glob(env.Path(g + ".after"))
			m = append(m, extra...)
		}
		for _, full := range m {
			hostPath := "/" + strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(full, env.Path("/")), ".after"), "/")
			if seen[hostPath] {
				continue
			}
			seen[hostPath] = true
			st, err := os.Stat(full)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			mt := env.ModTime(hostPath, st)
			out = append(out, Backup{
				Path: hostPath, Domain: DomainFromName(filepath.Base(hostPath)), Bytes: st.Size(),
				Modified:   mt.UTC().Format(time.RFC3339),
				AgeHours:   float64(int(now.Sub(mt).Hours()*10)) / 10,
				GUIVisible: filepath.Dir(hostPath) == GUIDir,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified > out[j].Modified })
	return out, nil
}

// Check is one verification result.
type Check struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is the verification output.
type Report struct {
	Schema        string   `json:"schema"`
	Path          string   `json:"path"`
	Entries       int      `json:"entries"`
	Bytes         int64    `json:"bytes"`
	GUICompatible *bool    `json:"gui_compatible,omitempty"`
	Checks        []Check  `json:"checks"`
	Databases     []string `json:"databases"`
	OK            bool     `json:"ok"`
}

type meta struct {
	MasterDomain string `xml:"masterDomain"`
}

// Verify reads the whole archive (proving it decompresses to EOF) and, when
// gui is true, applies the CyberPanel GUI-restore checks.
func Verify(env adapters.Env, hostPath string, gui bool) (Report, error) {
	r := Report{Schema: "hostops.backup-verify.v1", Path: hostPath, Checks: []Check{}, Databases: []string{}}
	f, err := os.Open(env.Path(hostPath))
	if os.IsNotExist(err) {
		if m, ok := env.Run.(interface{ Mutated() bool }); ok && m.Mutated() {
			f, err = os.Open(env.Path(hostPath) + ".after")
		}
	}
	if err != nil {
		return r, err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	if st, err := f.Stat(); err == nil {
		r.Bytes = st.Size()
	}
	add := func(id string, ok bool, detail string) { r.Checks = append(r.Checks, Check{id, ok, detail}) }

	var metaDomain string
	var total int64
	hasMeta, hasHome := false, false
	integrity := func() error {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			r.Entries++
			name := strings.TrimPrefix(h.Name, "./")
			switch {
			case name == "meta.xml":
				hasMeta = true
				var m meta
				b, _ := io.ReadAll(io.LimitReader(tr, 1<<20))
				if xml.Unmarshal(b, &m) == nil {
					metaDomain = strings.TrimSpace(m.MasterDomain)
				}
			case name == "public_html.tar.gz" || strings.HasPrefix(name, "public_html/"):
				hasHome = true
			case !strings.Contains(name, "/") && (strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".sql.gz")):
				r.Databases = append(r.Databases, strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".sql"))
			}
			// Bound decompression so a gzip bomb cannot pin a CPU forever.
			n, err := io.Copy(io.Discard, io.LimitReader(tr, maxUncompressed-total+1))
			total += n
			if err != nil {
				return err
			}
			if total > maxUncompressed {
				return fmt.Errorf("archive expands beyond %d GiB; refusing to read further", maxUncompressed>>30)
			}
		}
	}
	if err := integrity(); err != nil {
		add("integrity", false, "archive does not decompress cleanly: "+err.Error())
	} else {
		add("integrity", r.Entries > 0, fmt.Sprintf("%d entries read to EOF", r.Entries))
	}
	add("site_files", hasHome, map[bool]string{true: "public_html present", false: "no public_html in archive"}[hasHome])
	if gui {
		base := filepath.Base(hostPath)
		m := nameRE.FindStringSubmatch(base)
		add("gui_name", m != nil, "name must match backup-<domain>-MM.DD.YYYY_HH-MM-SS.tar.gz")
		inDir := filepath.Dir(hostPath) == GUIDir
		add("gui_location", inDir, map[bool]string{true: "in " + GUIDir, false: "restore page only lists " + GUIDir + "/; copy the file there"}[inDir])
		add("gui_meta", hasMeta && metaDomain != "", map[bool]string{true: "meta.xml masterDomain=" + metaDomain, false: "meta.xml with <masterDomain> missing at archive root"}[hasMeta && metaDomain != ""])
		if m != nil && metaDomain != "" {
			add("gui_domain_match", m[1] == metaDomain, fmt.Sprintf("file name domain %q vs meta.xml %q", m[1], metaDomain))
		}
	}
	r.OK = true
	for _, c := range r.Checks {
		r.OK = r.OK && c.OK
	}
	if gui {
		g := r.OK
		r.GUICompatible = &g
	}
	return r, nil
}

// Generic is the panel-less backup implementation (tar of the site home).
type Generic struct {
	Env adapters.Env
}

func (g *Generic) Name() string { return "generic" }

// stamp is hour-granular so a dry-run plan stays valid for its token window.
func (g *Generic) stamp() string { return g.Env.Now().UTC().Format("20060102-15") }

// Target returns the archive path BackupCreateSteps will write.
func (g *Generic) Target(domain string) string {
	return filepath.Join(g.Env.Cfg.BackupDir, domain+"-"+g.stamp()+".tar.gz")
}

func (g *Generic) BackupCreateSteps(domain string) []exec.Command {
	return []exec.Command{{ID: "backups.tar.create", Bin: exec.Tar, Mutates: true, Timeout: 30 * time.Minute, Args: []exec.Arg{
		exec.Lit("--create"), exec.Lit("--gzip"), exec.Lit("--file"), exec.Param(g.Target(domain)),
		exec.Lit("--directory"), exec.Lit(g.Env.Cfg.HomeRoot), exec.Param(domain)}}}
}

func (g *Generic) BackupRestoreSteps(file string) []exec.Command {
	return []exec.Command{{ID: "backups.tar.restore", Bin: exec.Tar, Mutates: true, Timeout: 30 * time.Minute, Args: []exec.Arg{
		exec.Lit("--extract"), exec.Lit("--gzip"), exec.Lit("--file"), exec.Param(file),
		exec.Lit("--directory"), exec.Lit(g.Env.Cfg.HomeRoot), exec.Lit("--no-overwrite-dir")}}}
}

func (g *Generic) BackupDirs(domain string) []string { return []string{g.Env.Cfg.BackupDir} }
