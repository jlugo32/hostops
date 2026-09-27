package mariadb

import (
	"os"
	"testing"
)

func TestParseSlowLog(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/mariadb/slow.log")
	if err != nil {
		t.Fatal(err)
	}
	qs := ParseSlowLog(b)
	if len(qs) != 2 {
		t.Fatalf("%+v", qs)
	}
	top := qs[0]
	if top.Count != 3 || top.Schema != "shop_db" || top.RowsExamined != 7500000 || top.MaxSec != 4.9 {
		t.Fatalf("%+v", top)
	}
	if top.Fingerprint != "select * from orders where customer_email = ? order by created_at desc limit ?" {
		t.Fatalf("fingerprint %q", top.Fingerprint)
	}
}

func TestFingerprintLists(t *testing.T) {
	if got := Fingerprint("SELECT a FROM t WHERE id IN (1, 2, 3) AND n = 'x''y'"); got != "select a from t where id in (?+) and n = ?" {
		t.Fatal(got)
	}
}

func TestParsers(t *testing.T) {
	v := ParseSlowVars([]byte("1\tslow.log\t2.000000\t/var/lib/mysql/\n"))
	if !v.Enabled || v.File != "/var/lib/mysql/slow.log" || v.LongSec != 2 {
		t.Fatalf("%+v", v)
	}
	s := ParseSize([]byte("shop_db\t1048576\t0\t12\nmysql\t2048\t0\t30\n"))
	if len(s) != 2 || s[0].Bytes != 1048576 || s[0].Tables != 12 {
		t.Fatalf("%+v", s)
	}
	if DumpCmd("shop_db;drop", "/x").Validate() == nil {
		t.Fatal("injection accepted")
	}
}
