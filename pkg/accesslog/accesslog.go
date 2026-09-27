// Package accesslog parses web server access logs from OpenLiteSpeed, nginx,
// Apache (Common and Combined formats) and Caddy (JSON). It depends only on
// the Go standard library so other tools can import it.
//
// OpenLiteSpeed quirk: CyberPanel writes logFormat with literal outer quotes,
// so every line is wrapped in an extra pair of '"'. The parser strips them.
package accesslog

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Format identifies the detected line format.
type Format string

const (
	Combined  Format = "combined"   // Apache/nginx/OLS combined
	Common    Format = "common"     // Apache common (no referer/UA)
	CaddyJSON Format = "caddy-json" // Caddy structured access log
)

// Entry is one parsed request.
type Entry struct {
	Remote    string    `json:"remote"`
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Proto     string    `json:"proto"`
	Status    int       `json:"status"`
	Bytes     int64     `json:"bytes"`
	Referer   string    `json:"referer,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Host      string    `json:"host,omitempty"`
	Format    Format    `json:"format"`
}

// ErrUnrecognized is returned for lines that match no known format.
var ErrUnrecognized = errors.New("accesslog: unrecognized line")

// clf matches Common, and Combined via the optional tail. Trailing fields
// (e.g. nginx "$http_x_forwarded_for") are tolerated.
var clf = regexp.MustCompile(`^(\S+) \S+ (?:\S+|"[^"]*") \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

const clfTime = "02/Jan/2006:15:04:05 -0700"

// ParseLine parses one line in any supported format.
func ParseLine(line string) (Entry, error) {
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, "{") {
		return parseCaddy(line)
	}
	// OLS/CyberPanel outer quotes: "1.2.3.4 - - [...] "GET / HTTP/1.1" 200 5 "-" "UA""
	if len(line) > 2 && line[0] == '"' && line[len(line)-1] == '"' && !strings.HasPrefix(line, `""`) {
		inner := line[1 : len(line)-1]
		if clf.MatchString(inner) {
			line = inner
		}
	}
	idx := clf.FindStringSubmatchIndex(line)
	if idx == nil {
		return Entry{}, ErrUnrecognized
	}
	m := make([]string, len(idx)/2)
	for i := range m {
		if idx[2*i] >= 0 {
			m[i] = line[idx[2*i]:idx[2*i+1]]
		}
	}
	e := Entry{Remote: m[1], Format: Common}
	t, err := time.Parse(clfTime, m[2])
	if err != nil {
		return Entry{}, ErrUnrecognized
	}
	e.Time = t
	req := unescape(m[3])
	parts := strings.SplitN(req, " ", 3)
	switch len(parts) {
	case 3:
		e.Method, e.Path, e.Proto = parts[0], parts[1], parts[2]
	case 2:
		e.Method, e.Path = parts[0], parts[1]
	default:
		e.Path = req // e.g. "-" or garbage probes
	}
	e.Status, _ = strconv.Atoi(m[4])
	if m[5] != "-" {
		e.Bytes, _ = strconv.ParseInt(m[5], 10, 64)
	}
	if idx[12] >= 0 { // the referer/UA group participated

		e.Format = Combined
		e.Referer, e.UserAgent = dash(unescape(m[6])), dash(unescape(m[7]))
	}
	return e, nil
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type caddyLine struct {
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Host     string              `json:"host"`
		Method   string              `json:"method"`
		URI      string              `json:"uri"`
		Proto    string              `json:"proto"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Status int   `json:"status"`
	Size   int64 `json:"size"`
}

func parseCaddy(line string) (Entry, error) {
	var c caddyLine
	if err := json.Unmarshal([]byte(line), &c); err != nil || c.Request.Method == "" {
		return Entry{}, ErrUnrecognized
	}
	sec, frac := math.Modf(c.TS)
	e := Entry{
		Remote: c.Request.ClientIP, Time: time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Method: c.Request.Method, Path: c.Request.URI, Proto: c.Request.Proto,
		Status: c.Status, Bytes: c.Size, Host: c.Request.Host, Format: CaddyJSON,
	}
	if e.Remote == "" {
		e.Remote = c.Request.RemoteIP
	}
	if v := c.Request.Headers["User-Agent"]; len(v) > 0 {
		e.UserAgent = v[0]
	}
	if v := c.Request.Headers["Referer"]; len(v) > 0 {
		e.Referer = v[0]
	}
	return e, nil
}

// Scanner reads entries from a stream, counting lines it could not parse.
type Scanner struct {
	sc      *bufio.Scanner
	cur     Entry
	Lines   int
	Skipped int
}

// NewScanner returns a Scanner over r. Lines up to 1 MiB are supported.
func NewScanner(r io.Reader) *Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	return &Scanner{sc: sc}
}

// Next advances to the next parseable entry.
func (s *Scanner) Next() bool {
	for s.sc.Scan() {
		s.Lines++
		line := s.sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := ParseLine(line)
		if err != nil {
			s.Skipped++
			continue
		}
		s.cur = e
		return true
	}
	return false
}

// Entry returns the current entry.
func (s *Scanner) Entry() Entry { return s.cur }

// Err returns the first read error.
func (s *Scanner) Err() error { return s.sc.Err() }
