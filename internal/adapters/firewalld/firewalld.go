// Package firewalld reads firewalld state. hostops v0.1 never changes
// firewall rules; see docs/threat-model.md.
package firewalld

import (
	"strings"

	"github.com/jlugo32/hostops/internal/exec"
)

// StateCmd reports whether firewalld is running.
func StateCmd() exec.Command {
	return exec.Command{ID: "firewalld.state", Bin: exec.FirewallCmd, Args: []exec.Arg{exec.Lit("--state")}}
}

// ListCmd lists the active zones with their full configuration.
func ListCmd() exec.Command {
	return exec.Command{ID: "firewalld.list", Bin: exec.FirewallCmd, Args: []exec.Arg{exec.Lit("--list-all-zones")}}
}

// Zone is one parsed zone.
type Zone struct {
	Name       string   `json:"zone"`
	Active     bool     `json:"active"`
	Default    bool     `json:"default"`
	Target     string   `json:"target"`
	Interfaces []string `json:"interfaces"`
	Sources    []string `json:"sources"`
	Services   []string `json:"services"`
	Ports      []string `json:"ports"`
	RichRules  []string `json:"rich_rules"`
}

// ParseZones parses `firewall-cmd --list-all-zones`, keeping only zones that
// are active or default (the rest cannot affect traffic).
func ParseZones(out []byte) []Zone {
	var zs []Zone
	var cur *Zone
	inRich := false
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			name, flags, _ := strings.Cut(l, " ")
			zs = append(zs, Zone{Name: name, Active: strings.Contains(flags, "active"), Default: strings.Contains(flags, "default"),
				Interfaces: []string{}, Sources: []string{}, Services: []string{}, Ports: []string{}, RichRules: []string{}})
			cur, inRich = &zs[len(zs)-1], false
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		if inRich && strings.HasPrefix(t, "rule ") {
			cur.RichRules = append(cur.RichRules, t)
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		inRich = false
		f := strings.Fields(v)
		switch k {
		case "target":
			cur.Target = strings.TrimSpace(v)
		case "interfaces":
			cur.Interfaces = append(cur.Interfaces, f...)
		case "sources":
			cur.Sources = append(cur.Sources, f...)
		case "services":
			cur.Services = append(cur.Services, f...)
		case "ports":
			cur.Ports = append(cur.Ports, f...)
		case "rich rules":
			inRich = true
		}
	}
	var out2 []Zone
	for _, z := range zs {
		if z.Active || z.Default {
			out2 = append(out2, z)
		}
	}
	return out2
}
