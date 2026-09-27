package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jlugo32/hostops/internal/hosterr"
)

type tab struct{ A string }

func (t tab) Table() ([]string, [][]string) { return []string{"A"}, [][]string{{t.A}} }

func TestFormatSelection(t *testing.T) {
	var o, e bytes.Buffer
	if New(&o, &e, false, false, Options{}).Format != JSON {
		t.Fatal("non-TTY must default to JSON")
	}
	if New(&o, &e, true, true, Options{}).Format != Human {
		t.Fatal("TTY must default to human")
	}
	if New(&o, &e, true, true, Options{Plain: true}).Format != Plain {
		t.Fatal("--plain")
	}
	if New(&o, &e, true, true, Options{JSON: true}).Format != JSON {
		t.Fatal("--json")
	}
}

func TestNoColor(t *testing.T) {
	var o, e bytes.Buffer
	t.Setenv("NO_COLOR", "")
	if New(&o, &e, true, true, Options{}).Color {
		t.Fatal("NO_COLOR set (even empty) must disable colour")
	}
}

func TestPlainEscapesControlChars(t *testing.T) {
	var o, e bytes.Buffer
	p := &Printer{Out: &o, Err: &e, Format: Plain}
	p.Result(tab{A: "evil\x1b[31m\nsecond"})
	if strings.Contains(o.String(), "\x1b") || strings.Count(o.String(), "\n") != 1 {
		t.Fatalf("unsafe plain output %q", o.String())
	}
}

func TestErrorJSONOnStderrOnly(t *testing.T) {
	var o, e bytes.Buffer
	p := &Printer{Out: &o, Err: &e, Format: JSON}
	p.Error(hosterr.New(3, "bad"))
	if o.Len() != 0 || !strings.Contains(e.String(), `"kind": "validation"`) {
		t.Fatalf("stdout=%q stderr=%q", o.String(), e.String())
	}
	e.Reset()
	(&Printer{Out: &o, Err: &e, Format: Human}).Error(errors.New("boom"))
	if !strings.Contains(e.String(), "exit 1") {
		t.Fatalf("%q", e.String())
	}
}
