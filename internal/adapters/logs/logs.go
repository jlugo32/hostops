// Package logs summarises access logs (via pkg/accesslog) for triage.
package logs

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/jlugo32/hostops/pkg/accesslog"
)

// Count is one ranked value.
type Count struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Top is the summary of an access log window.
type Top struct {
	Schema     string  `json:"schema"`
	Source     string  `json:"source"`
	Lines      int     `json:"lines_read"`
	Parsed     int     `json:"parsed"`
	Skipped    int     `json:"skipped"`
	First      string  `json:"first,omitempty"`
	Last       string  `json:"last,omitempty"`
	Status     []Count `json:"status"`
	IPs        []Count `json:"top_ips"`
	Paths      []Count `json:"top_paths"`
	UserAgents []Count `json:"top_user_agents"`
	Errors5xx  int     `json:"errors_5xx"`
	Errors4xx  int     `json:"errors_4xx"`
	Probes     []Count `json:"probe_paths"`
	ProbeIPs   []Count `json:"probe_ips"`
}

// probeMarkers are paths only scanners request on a non-WordPress PHP host.
var probeMarkers = []string{"/.env", "/.git", "/wp-login.php", "/xmlrpc.php", "/wp-admin", "/phpmyadmin", "/.aws", "/vendor/phpunit", "/cgi-bin/", "/boaform", "/actuator"}

// IsProbe reports whether path looks like vulnerability scanning.
func IsProbe(path string) bool {
	p := strings.ToLower(path)
	for _, m := range probeMarkers {
		if strings.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

// Tail returns at most the last n lines of b.
func Tail(b []byte, n int) []byte {
	b = bytes.TrimRight(b, "\n")
	idx := len(b)
	for i := 0; i < n; i++ {
		j := bytes.LastIndexByte(b[:idx], '\n')
		if j < 0 {
			return b
		}
		idx = j
	}
	return b[idx+1:]
}

// Summarize parses b and ranks the top k values of each dimension.
func Summarize(source string, b []byte, k int) Top {
	t := Top{Schema: "hostops.logs-top.v1", Source: source}
	status, ips, paths, uas, probes, probeIPs := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	s := accesslog.NewScanner(bytes.NewReader(b))
	for s.Next() {
		e := s.Entry()
		t.Parsed++
		ts := e.Time.UTC().Format("2006-01-02T15:04:05Z")
		if t.First == "" || ts < t.First {
			t.First = ts
		}
		if ts > t.Last {
			t.Last = ts
		}
		status[strconv.Itoa(e.Status)]++
		ips[e.Remote]++
		path := e.Path
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		paths[path]++
		if e.UserAgent != "" {
			uas[e.UserAgent]++
		}
		switch {
		case e.Status >= 500:
			t.Errors5xx++
		case e.Status >= 400:
			t.Errors4xx++
		}
		if IsProbe(path) {
			probes[path]++
			probeIPs[e.Remote]++
		}
	}
	t.Lines, t.Skipped = s.Lines, s.Skipped
	t.Status, t.IPs, t.Paths, t.UserAgents = rank(status, k), rank(ips, k), rank(paths, k), rank(uas, k)
	t.Probes, t.ProbeIPs = rank(probes, k), rank(probeIPs, k)
	return t
}

func rank(m map[string]int, k int) []Count {
	out := make([]Count, 0, len(m))
	for v, c := range m {
		out = append(out, Count{v, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}
