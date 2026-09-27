package openlitespeed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlugo32/hostops/internal/adapters"
	"github.com/jlugo32/hostops/internal/config"
	"github.com/jlugo32/hostops/internal/exec"
)

const server = `
virtualHost Example{
    vhRoot                   Example/
}
listener Default{
  map                     good.example good.example
  map                     typo.example typo.example
}
listener SSL {
  map                     good.example good.example
}
virtualHost good.example {
  vhRoot                  /home/$VH_NAME
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
}
virtualHost typo.example {
  vhRoot                  /home/$VH_NAME
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
}
virtualHost orphan.example {
  vhRoot                  /home/$VH_NAME
  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf
}
`

const goodVhost = `docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME
vhAliases                 www.$VH_NAME
accesslog $VH_ROOT/logs/$VH_NAME.access_log {
  useServer               0
  logFormat               "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i""
}
extprocessor good1234 {
  path                    /usr/local/lsws/lsphp85/bin/lsphp
}
context / {
  extraHeaders            <<<END_extraHeaders
Strict-Transport-Security: max-age=31536000
END_extraHeaders
}
vhssl  {
  keyFile                 /etc/letsencrypt/live/good.example/privkey.pem
  certFile                /etc/letsencrypt/live/good.example/fullchain.pem
}
`

func tree(t *testing.T, files map[string]string) adapters.Env {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if strings.HasSuffix(p, "/") {
			os.MkdirAll(full, 0o755)
			continue
		}
		os.WriteFile(full, []byte(c), 0o644)
	}
	cfg := config.Defaults()
	cfg.Root = root
	return adapters.Env{Run: exec.NewFixtureRunner(root, false), Cfg: cfg}
}

func TestSites(t *testing.T) {
	env := tree(t, map[string]string{
		"usr/local/lsws/conf/httpd_config.conf":              server,
		"usr/local/lsws/conf/vhosts/good.example/vhost.conf": goodVhost,
		"usr/local/lsws/conf/vhosts/typo.example/vhost.conf": "docRot $VH_ROOT/public_html\n",
		"home/good.example/public_html/":                     "",
		"etc/letsencrypt/live/good.example/fullchain.pem":    "x",
	})
	a := &Adapter{Env: env}
	sites, err := a.Sites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 3 {
		t.Fatalf("got %d sites", len(sites))
	}
	g := sites[0]
	if g.Domain != "good.example" || g.DocRoot != "/home/good.example/public_html" || len(g.Problems) != 0 {
		t.Fatalf("good: %+v", g)
	}
	if g.PHP != "lsphp85" || g.AccessLog != "/home/good.example/logs/good.example.access_log" || g.Aliases[0] != "www.good.example" {
		t.Fatalf("good details: %+v", g)
	}
	if strings.Join(g.Listeners, ",") != "Default,SSL" {
		t.Fatalf("listeners %v", g.Listeners)
	}
	orphan, typo := sites[1], sites[2]
	if !strings.Contains(strings.Join(orphan.Problems, ";"), "unreadable") || !strings.Contains(strings.Join(orphan.Problems, ";"), "listener") {
		t.Fatalf("orphan: %+v", orphan.Problems)
	}
	p := strings.Join(typo.Problems, ";")
	if !strings.Contains(p, `unknown directive "docRot"`) || !strings.Contains(p, "no docRoot") {
		t.Fatalf("typo: %v", typo.Problems)
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"unclosed": "context / {\n  location x\n",
		"extra":    "docRoot x\n}\n",
		"heredoc":  "extraHeaders <<<END_x\nfoo\n",
		"stray":    "docRoot /x}\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Parse([]byte(goodVhost)); err != nil {
		t.Fatalf("good vhost: %v", err)
	}
}

func TestReloadIsDeclaredMutation(t *testing.T) {
	st := (&Adapter{}).ReloadSteps()
	if len(st) != 1 || !st[0].Mutates || st[0].String() != "systemctl reload lsws" {
		t.Fatalf("%+v", st)
	}
}
