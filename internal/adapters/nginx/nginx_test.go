package nginx

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/exec"
)

const conf = `
# managed by hand
server {
    listen 80;
    server_name example.org www.example.org;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name example.org www.example.org;
    root /var/www/example.org/html;
    ssl_certificate /etc/letsencrypt/live/example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.org/privkey.pem;
    access_log /var/log/nginx/example.org.access.log combined;
    location / { try_files $uri $uri/ =404; }
    location ~ \.php$ { include snippets/fastcgi-php.conf; }
}
server { listen 80 default_server; server_name _; return 444; }
`

func TestSites(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "etc/nginx/sites-enabled/example.org")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(conf), 0o644)
	os.MkdirAll(filepath.Join(root, "var/www/example.org/html"), 0o755)
	cfg := config.Defaults()
	cfg.Root = root
	a := &Adapter{Env: adapters.Env{Run: exec.NewFixtureRunner(root, false), Cfg: cfg}}
	sites, err := a.Sites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("%+v", sites)
	}
	s := sites[0]
	if s.DocRoot != "/var/www/example.org/html" || s.AccessLog != "/var/log/nginx/example.org.access.log" || len(s.Listeners) != 2 || s.Aliases[0] != "www.example.org" {
		t.Fatalf("%+v", s)
	}
	if len(s.Problems) != 1 { // cert file is not in the fake tree
		t.Fatalf("problems %v", s.Problems)
	}
}

func TestReloadTestsFirst(t *testing.T) {
	st := (&Adapter{}).ReloadSteps()
	if st[0].Mutates || st[0].String() != "nginx -t -q" || !st[1].Mutates {
		t.Fatalf("%v", st)
	}
}
