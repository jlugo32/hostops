package logs

import (
	"os"
	"testing"
)

func TestSummarize(t *testing.T) {
	b, _ := os.ReadFile("../../../testdata/accesslog/ols-cyberpanel.log")
	s := Summarize("x", b, 3)
	if s.Parsed != 8 || s.Skipped != 1 || s.Errors4xx != 5 {
		t.Fatalf("%+v", s)
	}
	if s.IPs[0].Value != "198.51.100.23" || s.IPs[0].Count != 3 {
		t.Fatalf("top ip %+v", s.IPs)
	}
	if s.Probes[0].Value != "/wp-login.php" || s.Probes[0].Count != 2 || len(s.ProbeIPs) != 2 {
		t.Fatalf("probes %+v %+v", s.Probes, s.ProbeIPs)
	}
}

func TestTail(t *testing.T) {
	if string(Tail([]byte("a\nb\nc\n"), 2)) != "b\nc" || string(Tail([]byte("a"), 5)) != "a" {
		t.Fatal("tail")
	}
}
