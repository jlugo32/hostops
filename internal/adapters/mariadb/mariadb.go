// Package mariadb runs fixed, read-only SQL through the mariadb client and
// parses the slow query log. Credentials come from the invoking user's
// ~/.my.cnf or unix-socket auth; hostops never accepts a password.
package mariadb

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jlugo32/hostops/internal/exec"
)

func query(id, sql string) exec.Command {
	return exec.Command{ID: id, Bin: exec.Mariadb, Args: []exec.Arg{exec.Lit("--batch"), exec.Lit("--skip-column-names"), exec.Lit("-e"), exec.Lit(sql)}}
}

// ListCmd lists databases.
func ListCmd() exec.Command { return query("mariadb.list", "SHOW DATABASES") }

// SizeCmd reports per-schema size and rows.
func SizeCmd() exec.Command {
	return query("mariadb.size", "SELECT table_schema, COALESCE(SUM(data_length+index_length),0), COALESCE(SUM(data_free),0), COUNT(*) FROM information_schema.tables GROUP BY table_schema ORDER BY 2 DESC")
}

// SlowVarsCmd reads slow-log settings.
func SlowVarsCmd() exec.Command {
	return query("mariadb.slowvars", "SELECT @@slow_query_log, @@slow_query_log_file, @@long_query_time, @@datadir")
}

// DumpCmd dumps one database to file without locking InnoDB tables.
func DumpCmd(db, file string) exec.Command {
	return exec.Command{ID: "mariadb.dump", Bin: exec.Mysqldump, Mutates: true, Args: []exec.Arg{
		exec.Lit("--single-transaction"), exec.Lit("--routines"), exec.Lit("--triggers"), exec.Lit("--result-file=" + file), exec.Param(db)}}
}

// System schemas are hidden from `db list` by default.
var System = map[string]bool{"information_schema": true, "performance_schema": true, "mysql": true, "sys": true}

// ParseList parses SHOW DATABASES output.
func ParseList(out []byte) []string {
	var res []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			res = append(res, l)
		}
	}
	return res
}

// Size is one schema's footprint.
type Size struct {
	Schema    string `json:"schema"`
	Bytes     int64  `json:"bytes"`
	FreeBytes int64  `json:"free_bytes"`
	Tables    int    `json:"tables"`
}

// ParseSize parses SizeCmd output.
func ParseSize(out []byte) []Size {
	var res []Size
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 4 {
			continue
		}
		s := Size{Schema: f[0]}
		s.Bytes, _ = strconv.ParseInt(f[1], 10, 64)
		s.FreeBytes, _ = strconv.ParseInt(f[2], 10, 64)
		s.Tables, _ = strconv.Atoi(f[3])
		res = append(res, s)
	}
	return res
}

// SlowVars is the slow-log configuration.
type SlowVars struct {
	Enabled bool    `json:"enabled"`
	File    string  `json:"file"`
	LongSec float64 `json:"long_query_time"`
	DataDir string  `json:"datadir"`
}

// ParseSlowVars parses SlowVarsCmd output. A relative log file is resolved
// against datadir, as the server does.
func ParseSlowVars(out []byte) SlowVars {
	f := strings.Split(strings.TrimSpace(string(out)), "\t")
	v := SlowVars{}
	if len(f) < 4 {
		return v
	}
	v.Enabled = f[0] == "1"
	v.File, v.DataDir = f[1], f[3]
	v.LongSec, _ = strconv.ParseFloat(f[2], 64)
	if v.File != "" && !strings.HasPrefix(v.File, "/") {
		v.File = strings.TrimSuffix(v.DataDir, "/") + "/" + v.File
	}
	return v
}

// SlowQuery aggregates one normalized statement.
type SlowQuery struct {
	Fingerprint  string  `json:"fingerprint"`
	Schema       string  `json:"schema,omitempty"`
	Count        int     `json:"count"`
	TotalSec     float64 `json:"total_sec"`
	MaxSec       float64 `json:"max_sec"`
	RowsExamined int64   `json:"rows_examined"`
	RowsSent     int64   `json:"rows_sent"`
	Example      string  `json:"example"`
}

var (
	qtRE   = regexp.MustCompile(`Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)`)
	schRE  = regexp.MustCompile(`Schema:\s*(\S+)`)
	strRE  = regexp.MustCompile(`'(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.)*"`)
	numRE  = regexp.MustCompile(`\b\d+(\.\d+)?\b`)
	listRE = regexp.MustCompile(`\(\s*\?(\s*,\s*\?)*\s*\)`)
	wsRE   = regexp.MustCompile(`\s+`)
)

// Fingerprint normalizes literals so identical statements group together.
func Fingerprint(sql string) string {
	s := strRE.ReplaceAllString(sql, "?")
	s = numRE.ReplaceAllString(s, "?")
	s = listRE.ReplaceAllString(s, "(?+)")
	s = wsRE.ReplaceAllString(strings.TrimSpace(s), " ")
	return strings.ToLower(strings.TrimSuffix(s, ";"))
}

// ParseSlowLog aggregates a MariaDB slow query log, worst total time first.
func ParseSlowLog(b []byte) []SlowQuery {
	agg := map[string]*SlowQuery{}
	var qt float64
	var sent, examined int64
	schema := ""
	var sql []string
	have := false
	flush := func() {
		if !have || len(sql) == 0 {
			sql, have = nil, false
			return
		}
		stmt := strings.Join(sql, " ")
		fp := Fingerprint(stmt)
		q, ok := agg[fp]
		if !ok {
			ex := stmt
			if len(ex) > 300 {
				ex = ex[:300] + "…"
			}
			q = &SlowQuery{Fingerprint: fp, Schema: schema, Example: ex}
			agg[fp] = q
		}
		q.Count++
		q.TotalSec += qt
		if qt > q.MaxSec {
			q.MaxSec = qt
		}
		q.RowsExamined += examined
		q.RowsSent += sent
		sql, have = nil, false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "# Time:") || strings.HasPrefix(l, "# User@Host:"):
			flush()
		case strings.HasPrefix(l, "# "):
			if m := schRE.FindStringSubmatch(l); m != nil {
				schema = m[1]
			}
			if m := qtRE.FindStringSubmatch(l); m != nil {
				flush()
				qt, _ = strconv.ParseFloat(m[1], 64)
				sent, _ = strconv.ParseInt(m[3], 10, 64)
				examined, _ = strconv.ParseInt(m[4], 10, 64)
				have = true
			}
		case strings.HasPrefix(l, "SET timestamp=") || strings.HasPrefix(strings.ToLower(l), "use "):
		case strings.HasPrefix(l, "/") && strings.Contains(l, "started with:"):
		case strings.HasPrefix(l, "Tcp port:") || strings.HasPrefix(l, "Time  "):
		default:
			if have && strings.TrimSpace(l) != "" {
				sql = append(sql, strings.TrimSpace(l))
			}
		}
	}
	flush()
	res := make([]SlowQuery, 0, len(agg))
	for _, q := range agg {
		q.TotalSec = float64(int64(q.TotalSec*1000+0.5)) / 1000
		res = append(res, *q)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].TotalSec != res[j].TotalSec {
			return res[i].TotalSec > res[j].TotalSec
		}
		return res[i].Fingerprint < res[j].Fingerprint
	})
	return res
}
