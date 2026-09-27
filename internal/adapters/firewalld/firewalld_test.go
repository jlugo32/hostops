package firewalld

import "testing"

const out = `block
  target: %%REJECT%%
  services:
public (default, active)
  target: default
  interfaces: eth0
  sources:
  services: dhcpv6-client http https ssh
  ports: 8090/tcp 7080/tcp 25/tcp 587/tcp
  rich rules:
	rule family="ipv4" source address="203.0.113.9" reject
trusted (active)
  target: ACCEPT
  sources: 192.0.2.77
`

func TestParseZones(t *testing.T) {
	zs := ParseZones([]byte(out))
	if len(zs) != 2 {
		t.Fatalf("%+v", zs)
	}
	p := zs[0]
	if !p.Default || len(p.Services) != 4 || len(p.Ports) != 4 || len(p.RichRules) != 1 || p.Interfaces[0] != "eth0" {
		t.Fatalf("%+v", p)
	}
	if zs[1].Sources[0] != "192.0.2.77" || zs[1].Target != "ACCEPT" {
		t.Fatalf("%+v", zs[1])
	}
}
