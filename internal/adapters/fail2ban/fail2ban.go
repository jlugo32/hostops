// Package fail2ban builds fail2ban-client commands and parses their output.
package fail2ban

import (
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/jlugo32/hostops/internal/exec"
)

// StatusCmd lists jails.
func StatusCmd() exec.Command {
	return exec.Command{ID: "fail2ban.status", Bin: exec.Fail2banClient, Args: []exec.Arg{exec.Lit("status")}}
}

// JailCmd shows one jail.
func JailCmd(jail string) exec.Command {
	return exec.Command{ID: "fail2ban.jail", Bin: exec.Fail2banClient, Args: []exec.Arg{exec.Lit("status"), exec.Param(jail)}}
}

// UnbanCmd removes ip from one jail, or from every jail when jail is "".
func UnbanCmd(jail, ip string) exec.Command {
	if jail == "" {
		return exec.Command{ID: "fail2ban.unban", Bin: exec.Fail2banClient, Mutates: true, Args: []exec.Arg{exec.Lit("unban"), exec.Param(ip)}}
	}
	return exec.Command{ID: "fail2ban.unban", Bin: exec.Fail2banClient, Mutates: true, Args: []exec.Arg{exec.Lit("set"), exec.Param(jail), exec.Lit("unbanip"), exec.Param(ip)}}
}

// BanCmd bans ip in jail.
func BanCmd(jail, ip string) exec.Command {
	return exec.Command{ID: "fail2ban.ban", Bin: exec.Fail2banClient, Mutates: true, Args: []exec.Arg{exec.Lit("set"), exec.Param(jail), exec.Lit("banip"), exec.Param(ip)}}
}

// ParseJails reads the "Jail list:" line of `fail2ban-client status`.
func ParseJails(out []byte) []string {
	for _, l := range strings.Split(string(out), "\n") {
		if _, v, ok := strings.Cut(l, "Jail list:"); ok {
			var js []string
			for _, j := range strings.Split(v, ",") {
				if j = strings.TrimSpace(j); j != "" {
					js = append(js, j)
				}
			}
			return js
		}
	}
	return nil
}

// Jail is one parsed jail status.
type Jail struct {
	Name            string   `json:"jail"`
	CurrentlyFailed int      `json:"currently_failed"`
	TotalFailed     int      `json:"total_failed"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	BannedIPs       []string `json:"banned_ips"`
}

// ParseJail reads `fail2ban-client status <jail>`.
func ParseJail(name string, out []byte) Jail {
	j := Jail{Name: name, BannedIPs: []string{}}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.TrimLeft(k, "|`- \t")
		v = strings.TrimSpace(v)
		n, _ := strconv.Atoi(v)
		switch k {
		case "Currently failed":
			j.CurrentlyFailed = n
		case "Total failed":
			j.TotalFailed = n
		case "Currently banned":
			j.CurrentlyBanned = n
		case "Total banned":
			j.TotalBanned = n
		case "Banned IP list":
			j.BannedIPs = append(j.BannedIPs, strings.Fields(v)...)
		}
	}
	return j
}

// SessionIP returns the client address of the current SSH session, if any.
// Banning it would lock the operator (or the agent's own transport) out.
func SessionIP() (netip.Addr, bool) {
	for _, k := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		if f := strings.Fields(os.Getenv(k)); len(f) > 0 {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}

// SelfLockout reports why banning ip would be unsafe, or "".
func SelfLockout(ip netip.Addr, protected []string) string {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "loopback/unspecified address"
	}
	if s, ok := SessionIP(); ok && s == ip {
		return "this is the address of the current SSH session"
	}
	for _, p := range protected {
		if pf, err := netip.ParsePrefix(p); err == nil && pf.Contains(ip) {
			return "address is in the protected list " + p
		}
		if pa, err := netip.ParseAddr(p); err == nil && pa == ip {
			return "address is in the protected list"
		}
	}
	return ""
}
