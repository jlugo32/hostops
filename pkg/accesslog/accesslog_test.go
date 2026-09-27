package accesslog

import (
	"os"
	"testing"
)

func scanFile(t *testing.T, name string) ([]Entry, *Scanner) {
	t.Helper()
	f, err := os.Open("../../testdata/accesslog/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := NewScanner(f)
	var out []Entry
	for s.Next() {
		out = append(out, s.Entry())
	}
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	return out, s
}

func TestOLSOuterQuotes(t *testing.T) {
	es, s := scanFile(t, "ols-cyberpanel.log")
	if len(es) != 8 || s.Skipped != 1 {
		t.Fatalf("got %d entries, %d skipped", len(es), s.Skipped)
	}
	e := es[0]
	if e.Remote != "203.0.113.10" || e.Method != "GET" || e.Status != 200 || e.Bytes != 87 || e.Format != Combined {
		t.Fatalf("%+v", e)
	}
	if e.UserAgent != "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)" {
		t.Fatalf("UA %q", e.UserAgent)
	}
	if e.Referer != "" {
		t.Fatalf("'-' referer should be empty, got %q", e.Referer)
	}
}

func TestNginxCombined(t *testing.T) {
	es, s := scanFile(t, "nginx-combined.log")
	if len(es) != 4 || s.Skipped != 0 {
		t.Fatalf("got %d, skipped %d", len(es), s.Skipped)
	}
	if es[1].Path != "/api/v1/items?q=a%20b" || es[1].Status != 500 || es[1].Referer != "https://example.org/x" {
		t.Fatalf("%+v", es[1])
	}
	if es[2].Method != "" || es[2].Status != 400 {
		t.Fatalf("TLS-probe line: %+v", es[2])
	}
	if es[3].Path != `/quote"inside` || es[3].UserAgent != `UA with "quotes"` {
		t.Fatalf("escaped quotes: %+v", es[3])
	}
}

func TestApacheCommon(t *testing.T) {
	es, _ := scanFile(t, "apache-common.log")
	if len(es) != 2 || es[0].Format != Common || es[1].Bytes != 0 || es[1].Status != 304 {
		t.Fatalf("%+v", es)
	}
	if es[0].Time.UTC().Hour() != 20 {
		t.Fatalf("timezone not applied: %v", es[0].Time)
	}
}

func TestCaddyJSON(t *testing.T) {
	es, s := scanFile(t, "caddy.json.log")
	if len(es) != 2 || s.Skipped != 1 {
		t.Fatalf("got %d skipped %d", len(es), s.Skipped)
	}
	if es[0].Remote != "203.0.113.50" || es[0].Host != "example.net" || es[0].Referer != "https://duckduckgo.com/" {
		t.Fatalf("%+v", es[0])
	}
	if es[1].Remote != "203.0.113.51" || es[1].Status != 429 {
		t.Fatalf("remote_ip fallback: %+v", es[1])
	}
}

func FuzzParseLine(f *testing.F) {
	for _, s := range []string{
		`1.2.3.4 - - [31/Aug/2026:06:45:37 +0000] "GET / HTTP/1.1" 200 1 "-" "x"`,
		`"1.2.3.4 - - [31/Aug/2026:06:45:37 +0000] "GET / HTTP/1.1" 200 1 "-" "x""`,
		`{"request":{"method":"GET"}}`, `""`, `"`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseLine(s) })
}
