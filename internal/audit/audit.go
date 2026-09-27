// Package audit writes the hash-chained JSONL audit log. Each line records one
// hostops invocation and carries the sha256 of the previous line, so deleting,
// reordering or editing any line breaks the chain and `hostops audit verify`
// reports the first bad line.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jlugo32/hostops/internal/hosterr"
)

// Genesis is the prev_sha256 of the first entry.
var Genesis = strings.Repeat("0", 64)

// Actor identifies who ran the command.
type Actor struct {
	User  string `json:"user"`
	Agent string `json:"agent,omitempty"`
}

// Entry is one audit record. Field order is fixed by the struct.
type Entry struct {
	TS           string   `json:"ts"`
	Actor        Actor    `json:"actor"`
	Command      string   `json:"command"`
	Argv         []string `json:"argv"`
	Mode         string   `json:"mode"`
	DryRun       bool     `json:"dry_run"`
	ConfirmToken string   `json:"confirm_token,omitempty"`
	ExitCode     int      `json:"exit_code"`
	ResultSHA256 string   `json:"result_sha256"`
	PrevSHA256   string   `json:"prev_sha256"`
}

// DefaultPath returns $HOSTOPS_AUDIT_LOG or the XDG state location.
func DefaultPath() string {
	if p := os.Getenv("HOSTOPS_AUDIT_LOG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "hostops", "audit.jsonl")
}

// CurrentActor reads the OS user and an optional agent id.
// HOSTOPS_AGENT_ID wins; otherwise Claude Code sessions are tagged generically.
func CurrentActor() Actor {
	a := Actor{User: "unknown"}
	if u, err := user.Current(); err == nil {
		a.User = u.Username
	}
	switch {
	case os.Getenv("HOSTOPS_AGENT_ID") != "":
		a.Agent = os.Getenv("HOSTOPS_AGENT_ID")
	case os.Getenv("CLAUDECODE") == "1":
		a.Agent = "claude-code"
	}
	a.User, a.Agent = Neutralize(a.User), Neutralize(a.Agent)
	return a
}

// Neutralize makes a string safe to store: invalid UTF-8 is replaced and
// C0/C1 control characters (newlines, ESC, NUL, bidi-free) are rendered as
// visible escapes. JSON encoding would already escape them, but neutralizing
// first means the value is also safe when later printed to a terminal.
func Neutralize(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Hash returns the hex sha256 of b.
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Log appends entries to one file.
type Log struct {
	Path string
	Now  func() time.Time
}

// Append writes e, filling ts and prev_sha256 under an exclusive file lock.
func (l *Log) Append(e Entry) (Entry, error) {
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return e, err
	}
	f, err := os.OpenFile(l.Path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return e, err
	}
	defer f.Close() //nolint:errcheck // durability comes from the checked Sync below
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return e, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck

	prev, err := lastLineHash(f)
	if err != nil {
		return e, err
	}
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	e.TS = now().UTC().Format(time.RFC3339Nano)
	e.PrevSHA256 = prev
	e.Command = Neutralize(e.Command)
	e.ConfirmToken = Neutralize(e.ConfirmToken)
	e.Mode = Neutralize(e.Mode)
	clean := make([]string, len(e.Argv))
	for i, a := range e.Argv {
		clean[i] = Neutralize(a)
	}
	e.Argv = clean
	line, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if bytes.ContainsAny(line, "\n\r") {
		return e, errors.New("audit: refusing to write a multi-line record")
	}
	if _, err := f.Seek(0, 2); err != nil {
		return e, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return e, err
	}
	return e, f.Sync()
}

func lastLineHash(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() == 0 {
		return Genesis, nil
	}
	// Read backwards in chunks until we hold the whole last line.
	const chunk = 4096
	size := st.Size()
	var buf []byte
	for off := size; off > 0; {
		n := int64(chunk)
		if off < n {
			n = off
		}
		off -= n
		part := make([]byte, n)
		if _, err := f.ReadAt(part, off); err != nil {
			return "", err
		}
		buf = append(part, buf...)
		trimmed := bytes.TrimRight(buf, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return Hash(trimmed[i+1:]), nil
		}
		if off == 0 {
			return Hash(trimmed), nil
		}
	}
	return Genesis, nil
}

// VerifyReport is the result of recomputing the chain.
type VerifyReport struct {
	Schema     string `json:"schema"`
	Path       string `json:"path"`
	Entries    int    `json:"entries"`
	OK         bool   `json:"ok"`
	FirstBad   int    `json:"first_bad_line,omitempty"`
	Reason     string `json:"reason,omitempty"`
	HeadSHA256 string `json:"head_sha256,omitempty"`
}

// Verify recomputes the chain in path.
func Verify(path string) (VerifyReport, error) {
	rep := VerifyReport{Schema: "hostops.audit-verify.v1", Path: path}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			rep.OK = true
			return rep, nil
		}
		return rep, hosterr.Wrap(hosterr.General, err, "opening audit log")
	}
	defer f.Close() //nolint:errcheck // read-only handle
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	prev := Genesis
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			rep.FirstBad, rep.Reason = n, "line is not a valid audit record"
			return rep, hosterr.New(hosterr.Verification, "audit chain broken at line %d: %s", n, rep.Reason)
		}
		if e.PrevSHA256 != prev {
			rep.FirstBad, rep.Reason = n, "prev_sha256 does not match previous line"
			return rep, hosterr.New(hosterr.Verification, "audit chain broken at line %d: %s", n, rep.Reason)
		}
		prev = Hash(line)
	}
	if err := sc.Err(); err != nil {
		return rep, hosterr.Wrap(hosterr.General, err, "reading audit log")
	}
	rep.Entries, rep.OK, rep.HeadSHA256 = n, true, prev
	return rep, nil
}

// TokenUsed reports whether token already authorized an executed (not
// dry-run, not refused) command. Confirm tokens are single-use.
func TokenUsed(path, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	needle := []byte(`"confirm_token":"` + token + `"`)
	for sc.Scan() {
		if !bytes.Contains(sc.Bytes(), needle) {
			continue
		}
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.ConfirmToken == token && !e.DryRun && e.ExitCode != hosterr.Confirm {
			return true, nil
		}
	}
	return false, sc.Err()
}
