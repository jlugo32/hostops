// Package output renders results. The rules (ADR-0002, clig.dev):
//   - stdout carries data only; stderr carries diagnostics, errors and the
//     exit-4 confirmation envelope.
//   - JSON when stdout is not a TTY, or with --json; --plain gives stable
//     tab-separated rows for grep/awk; a TTY gets aligned human tables.
//   - Colour only on a TTY, never with --no-color, NO_COLOR or TERM=dumb.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/jlugo32/hostops/internal/hosterr"
	"github.com/jlugo32/hostops/internal/validate"
)

// Format selects how results are printed.
type Format int

const (
	Human Format = iota
	JSON
	Plain
)

// Tabular results can render as rows in human and plain modes.
type Tabular interface {
	Table() (header []string, rows [][]string)
}

// Printer writes results and diagnostics.
type Printer struct {
	Out, Err io.Writer
	Format   Format
	Color    bool
	Quiet    bool
}

// IsTTY reports whether f is a character device.
func IsTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Options are the relevant global flags.
type Options struct {
	JSON, Plain, NoColor, Quiet bool
}

// New picks the format and colour for the current process.
func New(out, errw io.Writer, stdoutTTY, stderrTTY bool, o Options) *Printer {
	p := &Printer{Out: out, Err: errw, Quiet: o.Quiet}
	switch {
	case o.JSON:
		p.Format = JSON
	case o.Plain:
		p.Format = Plain
	case !stdoutTTY:
		p.Format = JSON
	default:
		p.Format = Human
	}
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	p.Color = stderrTTY && !o.NoColor && !noColorEnv && os.Getenv("TERM") != "dumb"
	return p
}

// Result prints v on stdout in the selected format.
func (p *Printer) Result(v any) error {
	if t, ok := v.(Tabular); ok && p.Format != JSON {
		h, rows := t.Table()
		if p.Format == Plain {
			for _, r := range rows {
				fmt.Fprintln(p.Out, strings.Join(sanitizeRow(r), "\t"))
			}
			return nil
		}
		tw := tabwriter.NewWriter(p.Out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, strings.Join(h, "\t"))
		for _, r := range rows {
			fmt.Fprintln(tw, strings.Join(sanitizeRow(r), "\t"))
		}
		return tw.Flush()
	}
	enc := json.NewEncoder(p.Out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Marshal returns the exact bytes Result would write in JSON mode. Used for
// the audit log's result_sha256.
func Marshal(v any) []byte {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return []byte(b.String())
}

func sanitizeRow(r []string) []string {
	out := make([]string, len(r))
	for i, c := range r {
		out[i] = validate.Printable(strings.ReplaceAll(c, "\t", " "))
	}
	return out
}

// Diag prints a diagnostic on stderr unless -q.
func (p *Printer) Diag(format string, a ...any) {
	if p.Quiet {
		return
	}
	fmt.Fprintf(p.Err, format+"\n", a...)
}

// Envelope always prints machine JSON on stderr: it is a protocol message.
func (p *Printer) Envelope(v any) {
	enc := json.NewEncoder(p.Err)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ErrorDoc is the JSON shape of an error on stderr.
type ErrorDoc struct {
	Schema string `json:"schema"`
	Error  struct {
		Code    int    `json:"code"`
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

// Error prints err on stderr: JSON in JSON mode, one line otherwise.
func (p *Printer) Error(err error) {
	code := hosterr.Code(err)
	msg := err.Error()
	if p.Format == JSON {
		d := ErrorDoc{Schema: "hostops.error.v1"}
		d.Error.Code, d.Error.Kind, d.Error.Message = code, hosterr.Kind(code), msg
		p.Envelope(d)
		return
	}
	prefix := "hostops: error: "
	if p.Color {
		prefix = "\x1b[31mhostops: error:\x1b[0m "
	}
	fmt.Fprintf(p.Err, "%s%s (exit %d)\n", prefix, msg, code)
}
