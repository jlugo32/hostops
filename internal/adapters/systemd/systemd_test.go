package systemd

import "testing"

func TestParseShow(t *testing.T) {
	out := []byte("Id=lsphp.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=oom-kill\nMainPID=0\nNRestarts=4\nMemoryCurrent=[not set]\nUnitFileState=enabled\n")
	s, err := ParseShow("lsphp", out)
	if err != nil {
		t.Fatal(err)
	}
	if s.Unit != "lsphp.service" || s.Healthy || s.Result != "oom-kill" || s.Restarts != 4 || s.MemoryBytes != 0 {
		t.Fatalf("%+v", s)
	}
	if _, err := ParseShow("x", []byte("garbage")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestProtected(t *testing.T) {
	for _, u := range []string{"sshd", "sshd.service", "firewalld", "NetworkManager.service"} {
		if !IsProtected(u) {
			t.Errorf("%s must be protected", u)
		}
	}
	if IsProtected("lsws") || IsProtected("mariadb.service") {
		t.Fatal("service units wrongly protected")
	}
}

func TestParseJournal(t *testing.T) {
	out := []byte(`{"__REALTIME_TIMESTAMP":"1790506800000000","PRIORITY":"3","_SYSTEMD_UNIT":"lsws.service","MESSAGE":"Out of memory: Killed process 4242 (lsphp)"}
{"__REALTIME_TIMESTAMP":"1790506801000000","PRIORITY":"6","MESSAGE":[104,105,255]}
not json
`)
	es := ParseJournal(out)
	if len(es) != 2 || es[0].Priority != 3 || es[0].Time != "2026-09-27T11:00:00Z" {
		t.Fatalf("%+v", es)
	}
	if es[1].Message != "hi�" {
		t.Fatalf("byte-array message: %q", es[1].Message)
	}
}

func TestCommandsValidate(t *testing.T) {
	if err := StatusCmd("lsws").Validate(); err != nil {
		t.Fatal(err)
	}
	if RestartCmd("lsws;reboot").Validate() == nil {
		t.Fatal("injection accepted")
	}
}
