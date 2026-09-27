package fail2ban

import (
	"net/netip"
	"testing"
)

const status = "Status\n|- Number of jail:\t3\n`- Jail list:\tdovecot, postfix-sasl, sshd\n"
const sshd = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t2\n|  |- Total failed:\t448\n|  `- File list:\t/var/log/secure\n`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t9\n   `- Banned IP list:\t198.51.100.7 203.0.113.9\n"

func TestParse(t *testing.T) {
	js := ParseJails([]byte(status))
	if len(js) != 3 || js[2] != "sshd" {
		t.Fatalf("%v", js)
	}
	j := ParseJail("sshd", []byte(sshd))
	if j.CurrentlyFailed != 2 || j.TotalFailed != 448 || j.CurrentlyBanned != 2 || j.TotalBanned != 9 || len(j.BannedIPs) != 2 {
		t.Fatalf("%+v", j)
	}
}

func TestSelfLockout(t *testing.T) {
	t.Setenv("SSH_CLIENT", "192.0.2.77 50022 22")
	t.Setenv("SSH_CONNECTION", "")
	if SelfLockout(netip.MustParseAddr("192.0.2.77"), nil) == "" {
		t.Fatal("own session IP not protected")
	}
	if SelfLockout(netip.MustParseAddr("127.0.0.1"), nil) == "" {
		t.Fatal("loopback not protected")
	}
	if SelfLockout(netip.MustParseAddr("10.1.2.3"), []string{"10.0.0.0/8"}) == "" {
		t.Fatal("protected prefix ignored")
	}
	if SelfLockout(netip.MustParseAddr("198.51.100.7"), []string{"10.0.0.0/8"}) != "" {
		t.Fatal("ordinary IP refused")
	}
}

func TestCommands(t *testing.T) {
	if UnbanCmd("", "1.2.3.4").String() != "fail2ban-client unban 1.2.3.4" {
		t.Fatal(UnbanCmd("", "1.2.3.4").String())
	}
	if BanCmd("sshd", "1.2.3.4").String() != "fail2ban-client set sshd banip 1.2.3.4" || !BanCmd("sshd", "1.2.3.4").Mutates {
		t.Fatal("ban")
	}
}
