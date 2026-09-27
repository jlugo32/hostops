// Package systemd builds systemctl/journalctl commands and parses their output.
package systemd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/exec"
	"github.com/jlugo32/hostops/internal/hosterr"
)

// Protected units are never restarted by hostops: restarting them can cut
// the operator's own session or the host's network. Fix them by hand.
var Protected = map[string]bool{
	"sshd": true, "ssh": true, "systemd-journald": true, "systemd-logind": true,
	"dbus": true, "dbus-broker": true, "networkmanager": true, "network": true,
	"systemd-networkd": true, "systemd-resolved": true, "firewalld": true, "auditd": true,
	"getty@tty1": true, "user@0": true,
}

// Normalize strips a trailing ".service".
func Normalize(unit string) string { return strings.TrimSuffix(unit, ".service") }

// IsProtected reports whether unit is on the do-not-restart list.
func IsProtected(unit string) bool { return Protected[strings.ToLower(Normalize(unit))] }

var showProps = "Id,LoadState,ActiveState,SubState,Result,MainPID,NRestarts,ExecMainStartTimestamp,MemoryCurrent,UnitFileState,Description"

// StatusCmd is a read-only systemctl show.
func StatusCmd(unit string) exec.Command {
	return exec.Command{ID: "systemd.show", Bin: exec.Systemctl, Args: []exec.Arg{
		exec.Lit("show"), exec.Param(unit), exec.Lit("--no-pager"), exec.Lit("--property=" + showProps)}}
}

// RestartCmd restarts a unit.
func RestartCmd(unit string) exec.Command {
	return exec.Command{ID: "systemd.restart", Bin: exec.Systemctl, Args: []exec.Arg{exec.Lit("restart"), exec.Param(unit)}, Mutates: true, Timeout: 120 * time.Second}
}

// Status is a parsed unit state.
type Status struct {
	Unit        string `json:"unit"`
	Description string `json:"description"`
	Load        string `json:"load_state"`
	Active      string `json:"active_state"`
	Sub         string `json:"sub_state"`
	Result      string `json:"result"`
	MainPID     int    `json:"main_pid"`
	Restarts    int    `json:"n_restarts"`
	Since       string `json:"since,omitempty"`
	MemoryBytes int64  `json:"memory_bytes,omitempty"`
	Enabled     string `json:"unit_file_state"`
	Healthy     bool   `json:"healthy"`
}

// ParseShow parses `systemctl show` key=value output.
func ParseShow(unit string, out []byte) (Status, error) {
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = v
		}
	}
	if kv["LoadState"] == "" {
		return Status{}, hosterr.New(hosterr.General, "unexpected systemctl show output for %s", unit)
	}
	s := Status{Unit: unit, Description: kv["Description"], Load: kv["LoadState"], Active: kv["ActiveState"], Sub: kv["SubState"],
		Result: kv["Result"], Since: kv["ExecMainStartTimestamp"], Enabled: kv["UnitFileState"]}
	if kv["Id"] != "" {
		s.Unit = kv["Id"]
	}
	s.MainPID, _ = strconv.Atoi(kv["MainPID"])
	s.Restarts, _ = strconv.Atoi(kv["NRestarts"])
	if m, err := strconv.ParseInt(kv["MemoryCurrent"], 10, 64); err == nil {
		s.MemoryBytes = m
	}
	s.Healthy = s.Load == "loaded" && s.Active == "active"
	return s, nil
}

// JournalCmd reads the last n lines of a unit's journal (or the whole
// journal when unit is empty), optionally filtered to priority <= prio.
func JournalCmd(unit string, n int, prio string) exec.Command {
	args := []exec.Arg{exec.Lit("--no-pager"), exec.Lit("-o"), exec.Lit("json"), exec.Lit("-n"), exec.Lit(strconv.Itoa(n))}
	if unit != "" {
		args = append(args, exec.Lit("-u"), exec.Param(unit))
	}
	if prio != "" {
		args = append(args, exec.Lit("-p"), exec.Lit(prio))
	}
	return exec.Command{ID: "systemd.journal", Bin: exec.Journalctl, Args: args}
}

// JournalEntry is one parsed journal record.
type JournalEntry struct {
	Time     string `json:"time"`
	Unit     string `json:"unit,omitempty"`
	Priority int    `json:"priority"`
	Ident    string `json:"identifier,omitempty"`
	Message  string `json:"message"`
}

// ParseJournal parses journalctl -o json lines. MESSAGE may be a string or a
// byte array (non-UTF-8 payloads); both are handled.
func ParseJournal(out []byte) []JournalEntry {
	var res []JournalEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var raw map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			continue
		}
		e := JournalEntry{Unit: str(raw["_SYSTEMD_UNIT"]), Ident: str(raw["SYSLOG_IDENTIFIER"]), Message: str(raw["MESSAGE"])}
		e.Priority, _ = strconv.Atoi(str(raw["PRIORITY"]))
		if us, err := strconv.ParseInt(str(raw["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			e.Time = time.UnixMicro(us).UTC().Format(time.RFC3339)
		}
		res = append(res, e)
	}
	return res
}

func str(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(r, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(r)
}
