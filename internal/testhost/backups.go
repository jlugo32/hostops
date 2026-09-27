package testhost

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
)

// TB is the subset of testing.TB the helpers need (so non-test code such as
// the fixture generator can pass its own implementation).
type TB interface {
	Helper()
	Fatal(args ...any)
}

func tgz(files map[string][]byte, order []string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range order {
		b := files[n]
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// CyberPanelBackup returns a CyberPanel-shaped archive for domain.
func CyberPanelBackup(domain string, withMeta bool) []byte {
	inner := tgz(map[string][]byte{"public_html/index.php": []byte("<?php echo 'hi';\n")}, []string{"public_html/index.php"})
	files := map[string][]byte{
		"./public_html.tar.gz": inner,
		"./shop_db.sql":        []byte("CREATE TABLE t (id int);\n"),
	}
	order := []string{"./public_html.tar.gz", "./shop_db.sql"}
	if withMeta {
		files["./meta.xml"] = []byte("<?xml version=\"1.0\"?>\n<metaFile><masterDomain>" + domain + "</masterDomain><phpSelection>PHP 8.5</phpSelection></metaFile>\n")
		order = append([]string{"./meta.xml"}, order...)
	}
	return tgz(files, order)
}

// WriteCyberPanelBackup writes CyberPanelBackup to path.
func WriteCyberPanelBackup(t TB, path, domain string, withMeta bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, CyberPanelBackup(domain, withMeta), 0o600); err != nil {
		t.Fatal(err)
	}
}
