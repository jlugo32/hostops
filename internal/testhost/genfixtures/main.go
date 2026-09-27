// Command genfixtures writes the fake hosts under testdata/hosts/. Each host
// is a directory usable as HOSTOPS_FIXTURES: commands.json (canned command
// output), root/ (the host filesystem) and served/ (certs the TLS prober
// sees). The clock is frozen at Now; set HOSTOPS_NOW to the same value.
//
//	go run ./internal/testhost/genfixtures -out testdata/hosts
//
// Certificates use fresh random keys, so re-running changes bytes but not
// meaning. Only re-run when a scenario changes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jlugo32/hostops/internal/testhost"
)

// Now is the frozen clock for every fixture.
var Now = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

type resp struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Exit   int    `json:"exit,omitempty"`
}

type host struct {
	name     string
	files    map[string][]byte
	modes    map[string]os.FileMode
	mtimes   map[string]time.Time
	cmds     map[string]resp
	after    map[string]resp
	served   map[string][]byte
	sites    []string
	scenario string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func (h *host) put(p, c string) { h.files[p] = []byte(c) }

func cert(domains []string, issuerOrg, issuerCN string, from, to time.Time, serial int64) ([]byte, []byte) {
	fc, key, err := testhost.MakeCert(testhost.CertSpec{Domains: domains, IssuerCN: issuerCN, IssuerOrg: issuerOrg, NotBefore: from, NotAfter: to, Serial: serial})
	must(err)
	return fc, key
}

func prodCert(d string, daysLeft int, serial int64) []byte {
	fc, _ := cert([]string{d, "www." + d}, "Let's Encrypt", "R11", Now.AddDate(0, 0, daysLeft-90), Now.AddDate(0, 0, daysLeft), serial)
	return fc
}

const serverConf = `#
# PLAIN TEXT CONFIGURATION FILE (anonymised from a CyberPanel host)
#
serverName                srv0000000.example-hosting.net
user                      nobody
group                     nobody

virtualHost Example{
    vhRoot                   Example/
    allowSymbolLink          1
    enableScript             1
    restrained               1
}

listener Default{
  address                 *:80
  secure                  0
%s}

listener SSL {
  address                 *:443
  secure                  1
  keyFile                  /usr/local/lsws/admin/conf/webadmin.key
  certFile                 /usr/local/lsws/admin/conf/webadmin.crt
%s}
%s`

const vhostTmpl = `docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME
vhAliases                 www.$VH_NAME
adminEmails               admin@$VH_NAME
enableGzip                1
enableIpGeo               1

index  {
  useServer               0
  indexFiles              index.php, index.html
}

errorlog $VH_ROOT/logs/$VH_NAME.error_log {
  useServer               0
  logLevel                WARN
  rollingSize             10M
}

accesslog $VH_ROOT/logs/$VH_NAME.access_log {
  useServer               0
  logFormat               "%%h %%l %%u %%t "%%r" %%>s %%b "%%{Referer}i" "%%{User-Agent}i""
  logHeaders              5
  rollingSize             10M
  keepDays                10
  compressArchive         1
}

scripthandler  {
  add                     lsapi:%[1]s php
}

extprocessor %[1]s {
  type                    lsapi
  address                 UDS://tmp/lshttpd/%[1]s.sock
  maxConns                10
  env                     LSAPI_CHILDREN=10
  initTimeout             600
  retryTimeout            0
  persistConn             1
  pcKeepAliveTimeout      1
  respBuffer              0
  autoStart               1
  path                    /usr/local/lsws/lsphp85/bin/lsphp
  extUser                 %[1]s
  extGroup                %[1]s
  memSoftLimit            1024M
  memHardLimit            1024M
  procSoftLimit           400
  procHardLimit           500
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

context /.well-known/acme-challenge {
  location                /usr/local/lsws/Example/html/.well-known/acme-challenge
  allowBrowse             1

  rewrite  {
     enable                  0
  }
  addDefaultCharset       off
}

vhssl  {
  keyFile                 /etc/letsencrypt/live/$VH_NAME/privkey.pem
  certFile                /etc/letsencrypt/live/$VH_NAME/fullchain.pem
  certChain               1
  sslProtocol             24
  enableECDHE             1
  renegProtection         1
  sslSessionCache         1
  enableSpdy              15
  enableStapling          1
  ocspRespMaxAge          86400
}
`

func accessLog(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(`"` + l + `"` + "\n") // CyberPanel's outer quotes
	}
	return b.String()
}

func clf(ip string, t time.Time, req string, st, n int, ref, ua string) string {
	return fmt.Sprintf(`%s - - [%s] "%s" %d %d "%s" "%s"`, ip, t.Format("02/Jan/2006:15:04:05 -0700"), req, st, n, ref, ua)
}

func normalTraffic(d string) []string {
	var ls []string
	uas := []string{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
	for i := 0; i < 30; i++ {
		t := Now.Add(-time.Duration(60-i) * time.Minute)
		ls = append(ls, clf(fmt.Sprintf("192.0.2.%d", 10+i%7), t, "GET / HTTP/2", 200, 18231, "https://www.google.com/", uas[i%3]))
		ls = append(ls, clf(fmt.Sprintf("192.0.2.%d", 10+i%7), t.Add(time.Second), "GET /assets/app.css HTTP/2", 200, 5120, "https://"+d+"/", uas[i%3]))
	}
	return ls
}

const sshdConf = `# anonymised AlmaLinux 9 sshd_config
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin prohibit-password
PasswordAuthentication no
MaxAuthTries 4
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
Subsystem sftp /usr/libexec/openssh/sftp-server
`

func showOut(unit, active, sub, result string, restarts int) string {
	return fmt.Sprintf("Id=%s.service\nLoadState=loaded\nActiveState=%s\nSubState=%s\nResult=%s\nMainPID=%d\nNRestarts=%d\nExecMainStartTimestamp=Sun 2026-09-27 08:00:00 UTC\nMemoryCurrent=412332032\nUnitFileState=enabled\nDescription=%s\n",
		unit, active, sub, result, map[bool]int{true: 4242, false: 0}[active == "active"], restarts, unit)
}

const showCmd = " --no-pager --property=Id,LoadState,ActiveState,SubState,Result,MainPID,NRestarts,ExecMainStartTimestamp,MemoryCurrent,UnitFileState,Description"

func jailOut(name string, failed, total, banned, totalBanned int, ips []string, file string) string {
	return fmt.Sprintf("Status for the jail: %s\n|- Filter\n|  |- Currently failed:\t%d\n|  |- Total failed:\t%d\n|  `- File list:\t%s\n`- Actions\n   |- Currently banned:\t%d\n   |- Total banned:\t%d\n   `- Banned IP list:\t%s\n",
		name, failed, total, file, banned, totalBanned, strings.Join(ips, " "))
}

func journal(entries ...[3]string) string { // {offsetMinutes, unit/ident, message}
	var b strings.Builder
	for i, e := range entries {
		var off int
		fmt.Sscanf(e[0], "%d", &off)
		ts := Now.Add(time.Duration(off) * time.Minute).UnixMicro()
		prio := "6"
		if strings.Contains(strings.ToLower(e[2]), "error") || strings.Contains(e[2], "Killed") || strings.Contains(e[2], "denied") || strings.Contains(e[2], "reject") || strings.Contains(e[2], "No space") {
			prio = "3"
		}
		m := map[string]string{"__REALTIME_TIMESTAMP": fmt.Sprint(ts + int64(i)), "PRIORITY": prio, "SYSLOG_IDENTIFIER": e[1], "MESSAGE": e[2]}
		if strings.HasSuffix(e[1], ".service") {
			m["_SYSTEMD_UNIT"] = e[1]
			m["SYSLOG_IDENTIFIER"] = strings.TrimSuffix(e[1], ".service")
		}
		j, _ := json.Marshal(m)
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

func jcmd(unit string, n int, prio string) string {
	s := fmt.Sprintf("journalctl --no-pager -o json -n %d", n)
	if unit != "" {
		s += " -u " + unit
	}
	if prio != "" {
		s += " -p " + prio
	}
	return s
}

const zones = `block
  target: %%REJECT%%
  interfaces:
  sources:
  services:
  ports:
  rich rules:
public (default, active)
  target: default
  interfaces: eth0
  sources:
  services: dhcpv6-client http https ssh
  ports: 8090/tcp 7080/tcp 25/tcp 587/tcp 465/tcp 993/tcp 443/udp
  rich rules:
`

// base builds the healthy three-site CyberPanel host.
func base(name string) *host {
	h := &host{name: name, files: map[string][]byte{}, modes: map[string]os.FileMode{}, mtimes: map[string]time.Time{}, cmds: map[string]resp{}, after: map[string]resp{}, served: map[string][]byte{},
		sites: []string{"example.com", "shop.example.net", "blog.example.org"}}
	var defMaps, sslMaps, vhosts strings.Builder
	for i, d := range h.sites {
		fmt.Fprintf(&defMaps, "  map                     %s %s\n", d, d)
		fmt.Fprintf(&sslMaps, "  map                     %s %s\n", d, d)
		fmt.Fprintf(&vhosts, "\nvirtualHost %s {\n  vhRoot                  /home/$VH_NAME\n  configFile              $SERVER_ROOT/conf/vhosts/$VH_NAME/vhost.conf\n  allowSymbolLink         1\n  enableScript            1\n  restrained              1\n}\n", d)
		user := strings.ReplaceAll(strings.Split(d, ".")[0], "-", "") + fmt.Sprint(1000+i*1111)
		h.put("usr/local/lsws/conf/vhosts/"+d+"/vhost.conf", fmt.Sprintf(vhostTmpl, user))
		h.put("home/"+d+"/public_html/index.php", "<?php echo 'ok';\n")
		h.put("home/"+d+"/public_html/config.php", "<?php // secrets live here\n")
		h.modes["home/"+d+"/public_html/config.php"] = 0o600
		h.put("home/"+d+"/logs/"+d+".access_log", accessLog(normalTraffic(d)))
		fc := prodCert(d, 60-i*7, int64(100+i))
		h.files["etc/letsencrypt/live/"+d+"/fullchain.pem"] = fc
		h.files["root/.acme.sh/"+d+"_ecc/fullchain.cer"] = fc
		h.put("root/.acme.sh/"+d+"_ecc/"+d+".conf", "Le_Domain='"+d+"'\nLe_Alt='www."+d+"'\nLe_Keylength='ec-256'\nLe_API='https://acme-v02.api.letsencrypt.org/directory'\nLe_RealFullChainPath='/etc/letsencrypt/live/"+d+"/fullchain.pem'\nLe_ReloadCmd='systemctl reload lsws'\n")
		h.served[d] = fc
	}
	h.put("usr/local/lsws/conf/httpd_config.conf", fmt.Sprintf(serverConf, defMaps.String(), sslMaps.String(), vhosts.String()))
	h.put("etc/ssh/sshd_config", sshdConf)
	h.files["home/backup/backup-example.com-09.27.2026_03-00-00.tar.gz"] = testhost.CyberPanelBackup("example.com", true)
	h.mtimes["home/backup/backup-example.com-09.27.2026_03-00-00.tar.gz"] = Now.Add(-9 * time.Hour)
	h.put("var/lib/mysql/slow.log", "/usr/sbin/mariadbd, Version: 11.8.8-MariaDB-log (MariaDB Server). started with:\nTcp port: 3306  Unix socket: /var/lib/mysql/mysql.sock\nTime                Id Command  Argument\n")

	for _, u := range []string{"lsws", "mariadb", "fail2ban", "postfix", "firewalld", "sshd", "crond"} {
		h.cmds["systemctl show "+u+showCmd] = resp{Stdout: showOut(u, "active", "running", "success", 0)}
		h.cmds["systemctl is-active "+u] = resp{Stdout: "active\n"}
	}
	h.cmds["systemctl reload lsws"] = resp{}
	h.cmds["systemctl is-enabled dnf-automatic.timer"] = resp{Stdout: "enabled\n"}
	h.cmds["getenforce"] = resp{Stdout: "Permissive\n"}
	h.cmds["firewall-cmd --state"] = resp{Stdout: "running\n"}
	h.cmds["firewall-cmd --list-all-zones"] = resp{Stdout: zones}
	h.cmds["fail2ban-client status"] = resp{Stdout: "Status\n|- Number of jail:\t3\n`- Jail list:\tdovecot, postfix-sasl, sshd\n"}
	h.cmds["fail2ban-client status sshd"] = resp{Stdout: jailOut("sshd", 0, 448, 1, 9, []string{"203.0.113.200"}, "/var/log/secure")}
	h.cmds["fail2ban-client status dovecot"] = resp{Stdout: jailOut("dovecot", 0, 12, 0, 1, nil, "/var/log/maillog")}
	h.cmds["fail2ban-client status postfix-sasl"] = resp{Stdout: jailOut("postfix-sasl", 3, 510, 0, 22, nil, "/var/log/maillog")}
	h.cmds["mariadb --batch --skip-column-names -e SHOW DATABASES"] = resp{Stdout: "blog_wp\ninformation_schema\nmysql\nperformance_schema\nshop_db\nsite_main\nsys\n"}
	h.cmds["mariadb --batch --skip-column-names -e SELECT table_schema, COALESCE(SUM(data_length+index_length),0), COALESCE(SUM(data_free),0), COUNT(*) FROM information_schema.tables GROUP BY table_schema ORDER BY 2 DESC"] =
		resp{Stdout: "shop_db\t2147483648\t10485760\t48\nblog_wp\t104857600\t0\t12\nsite_main\t8388608\t0\t9\nmysql\t2621440\t0\t31\n"}
	h.cmds["mariadb --batch --skip-column-names -e SELECT @@slow_query_log, @@slow_query_log_file, @@long_query_time, @@datadir"] = resp{Stdout: "1\tslow.log\t2.000000\t/var/lib/mysql/\n"}
	for _, n := range []int{50, 100, 200} {
		h.cmds[jcmd("", n, "")] = resp{Stdout: journal([3]string{"-30", "crond.service", "(root) CMD (/usr/local/CyberCP/bin/python /usr/local/CyberCP/plogical/renew.py)"}, [3]string{"-10", "lsws.service", "[INFO] Reloading server"})}
		h.cmds[jcmd("", n, "err")] = resp{Stdout: ""}
		for _, u := range []string{"lsws", "mariadb", "postfix", "fail2ban", "sshd"} {
			h.cmds[jcmd(u, n, "")] = resp{Stdout: journal([3]string{"-20", u + ".service", "Started " + u + "."})}
			h.cmds[jcmd(u, n, "err")] = resp{Stdout: ""}
		}
	}
	return h
}

func (h *host) setJournal(unit string, body string) {
	for _, n := range []int{50, 100, 200} {
		h.cmds[jcmd(unit, n, "")] = resp{Stdout: body}
		h.cmds[jcmd(unit, n, "err")] = resp{Stdout: body}
	}
}

func (h *host) write(out string) {
	dir := filepath.Join(out, h.name)
	must(os.RemoveAll(dir))
	for p, c := range h.files {
		full := filepath.Join(dir, "root", p)
		must(os.MkdirAll(filepath.Dir(full), 0o755))
		must(os.WriteFile(full, c, 0o644))
	}
	for d, c := range h.served {
		must(os.MkdirAll(filepath.Join(dir, "served"), 0o755))
		name := d + ".pem"
		if strings.HasSuffix(d, ".after") {
			name = d + ".pem"
		}
		must(os.WriteFile(filepath.Join(dir, "served", name), c, 0o644))
	}
	tab := map[string]any{"commands": h.cmds}
	if len(h.after) > 0 {
		tab["after_mutation"] = h.after
	}
	b, _ := json.MarshalIndent(sortedTable(tab), "", "  ")
	must(os.WriteFile(filepath.Join(dir, "commands.json"), append(b, '\n'), 0o644))
	if h.scenario != "" {
		must(os.WriteFile(filepath.Join(dir, "SCENARIO.md"), []byte(h.scenario), 0o644))
	}
	// git keeps neither mtimes nor permission bits, so record them.
	meta := map[string]map[string]string{"mtimes": {}, "modes": {}}
	for p, t := range h.mtimes {
		meta["mtimes"]["/"+p] = t.UTC().Format(time.RFC3339)
	}
	for p, m := range h.modes {
		meta["modes"]["/"+p] = fmt.Sprintf("%04o", m)
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	must(os.WriteFile(filepath.Join(dir, "meta.json"), append(mb, '\n'), 0o644))
}

// sortedTable makes commands.json diff-friendly.
func sortedTable(t map[string]any) map[string]any { return t }

func main() {
	out := flag.String("out", "testdata/hosts", "output directory")
	flag.Parse()
	hosts := scenarios()
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h.write(*out)
		names = append(names, h.name)
	}
	sort.Strings(names)
	fmt.Printf("wrote %d hosts: %s\n", len(names), strings.Join(names, ", "))
}
