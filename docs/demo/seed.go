//go:build ignore

// seed.go fills a sandbox with demo data for the README screenshots (see docs/screenshots.sh).
//
// It only writes through tussh's own packages, so the files have exactly the format tussh reads. It refuses
// to run unless TUSSH_CONFIG_DIR, TUSSH_STATE_DIR and TUSSH_KEYRING=file:… point into a sandbox, so it can
// never touch a real setup. All hosts are *.example names.
//
//	go run docs/demo/seed.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/policy"
	"github.com/baeroe/tussh/internal/secrets"
)

func main() {
	for _, v := range []string{"TUSSH_CONFIG_DIR", "TUSSH_STATE_DIR"} {
		if os.Getenv(v) == "" {
			fail("%s must point to a sandbox directory", v)
		}
	}
	if !strings.HasPrefix(os.Getenv("TUSSH_KEYRING"), "file:") {
		fail("TUSSH_KEYRING must be file:<path> (never the real keychain)")
	}
	if _, err := os.Stat(config.ConnectionsFile()); err == nil {
		fail("%s already exists; seed only an empty sandbox", config.ConnectionsFile())
	}

	ssh := "~/.ssh/"
	conns := []config.Connection{
		{Name: "shop-prod", Host: "web1.acme.example", User: "deploy", Auth: config.AuthKey, KeyPath: ssh + "acme_deploy",
			HasPassphrase: true, Favorite: true, Tags: []string{"acme", "prod"}, AccessLevel: config.LevelReadOnly,
			Description: "Acme online shop, production web server",
			Tunnels:     []config.Tunnel{{Name: "mysql", Local: 3307, RemoteHost: "127.0.0.1", RemotePort: 3306}}},
		{Name: "shop-staging", Host: "staging.acme.example", User: "deploy", Auth: config.AuthKey, KeyPath: ssh + "acme_deploy",
			HasPassphrase: true, Tags: []string{"acme", "staging"}, AccessLevel: config.LevelReadOnly,
			Description: "Staging, reset every night"},
		{Name: "shop-db", Host: "db1.acme.example", User: "ops", Auth: config.AuthKey, KeyPath: ssh + "acme_deploy",
			HasPassphrase: true, Tags: []string{"acme", "prod", "database"}, AccessLevel: config.LevelApproveEach,
			Description: "MySQL primary"},
		{Name: "homelab", Host: "nas.homelab.example", Port: 2222, User: "admin", Auth: config.AuthPassword,
			HasPassword: true, Favorite: true, Tags: []string{"homelab"}, AccessLevel: config.LevelTrusted,
			Description: "NAS with docker: media, backups, grafana",
			Tunnels:     []config.Tunnel{{Name: "grafana", Local: 3000, RemoteHost: "localhost", RemotePort: 3000}}},
		{Name: "pi-hole", Host: "pi.homelab.example", User: "pi", Auth: config.AuthKey, KeyPath: ssh + "homelab_rsa",
			Tags: []string{"homelab"}, AccessLevel: config.LevelNone, Description: "DNS, not for agents"},
		{Name: "ci-runner", Host: "runner1.example.net", User: "ci", Auth: config.AuthKey, KeyPath: ssh + "id_ed25519",
			Tags: []string{"ci"}, AccessLevel: config.LevelReadOnly, Description: "Self-hosted CI runner"},
		{Name: "blog", Host: "blog.example.org", User: "www", Auth: config.AuthKey, KeyPath: ssh + "id_ed25519",
			Tags: []string{"personal"}, AccessLevel: config.LevelReadOnly, Description: "Static site + nginx"},
	}
	byName := map[string]config.Connection{}
	kr := secrets.Open()
	_, err := config.Update(func(st *config.Store) error {
		for _, c := range conns {
			c, err := st.Upsert(c)
			if err != nil {
				return err
			}
			byName[c.Name] = c
			if c.HasPassword {
				must(kr.Set(secrets.Account(c.ID, secrets.KindPassword), "demo-password"))
			}
			if c.HasPassphrase {
				must(kr.Set(secrets.Account(c.ID, secrets.KindPassphrase), "demo-passphrase"))
			}
		}
		return nil
	})
	must(err)

	// last use: one file per connection, the mtime is the time of use
	now := time.Now()
	for name, ago := range map[string]time.Duration{"shop-prod": 4 * time.Minute, "homelab": 2 * time.Hour,
		"shop-staging": 26 * time.Hour, "shop-db": 3 * 24 * time.Hour, "blog": 9 * 24 * time.Hour} {
		id := byName[name].ID
		config.TouchUsed(id)
		t := now.Add(-ago)
		must(os.Chtimes(filepath.Join(config.StateDir(), "used", id), t, t))
	}

	// a remembered command ("approve & remember")
	_, err = allow.Add(byName["shop-staging"].ID, "shop-staging", "php bin/console cache:clear", 8*time.Hour, "tui")
	must(err)

	// audit log: reasons come from the real classifier and policy
	cl := classify.New()
	agentName := "claude-code 2.1.4"
	exit := func(n int) *int { return &n }
	type ev struct {
		ago                      time.Duration
		conn, cmd, decision, by  string
		justification, note, out string
		exit                     *int
		ms                       int64
	}
	events := []ev{
		{ago: 3 * time.Hour, conn: "blog", cmd: "uptime", decision: audit.Auto, exit: exit(0), ms: 412,
			out: " 09:12:44 up 41 days,  3:02,  0 users,  load average: 0.02, 0.04, 0.01\n"},
		{ago: 150 * time.Minute, conn: "pi-hole", cmd: "cat /etc/pihole/setupVars.conf", decision: audit.Blocked},
		{ago: 2 * time.Hour, conn: "homelab", cmd: "docker compose -f ~/media/compose.yml pull && docker compose -f ~/media/compose.yml up -d",
			decision: audit.Auto, exit: exit(0), ms: 18320, justification: "Update the media stack to the latest images",
			out: "[+] Pulling 3/3\n ✔ jellyfin Pulled\n ✔ sonarr Pulled\n ✔ radarr Pulled\n[+] Running 3/3\n ✔ Container media-jellyfin-1  Started\n"},
		{ago: 95 * time.Minute, conn: "ci-runner", cmd: "systemctl status gitlab-runner", decision: audit.Auto, exit: exit(0), ms: 655,
			out: "● gitlab-runner.service - GitLab Runner\n     Loaded: loaded (/etc/systemd/system/gitlab-runner.service; enabled)\n     Active: active (running) since Mon 2026-09-28 07:01:13 UTC; 5 days ago\n"},
		{ago: 80 * time.Minute, conn: "shop-staging", cmd: "php bin/console cache:clear", decision: audit.Approved, by: "tui",
			justification: "Clear the cache after the config change", exit: exit(0), ms: 2310,
			out: "\n // Clearing the cache for the prod environment with debug false\n\n [OK] Cache for the \"prod\" environment (debug=false) was successfully cleared.\n"},
		{ago: 50 * time.Minute, conn: "shop-staging", cmd: "php bin/console cache:clear", decision: audit.Approved, by: "remembered",
			exit: exit(0), ms: 2120, out: "\n [OK] Cache for the \"prod\" environment (debug=false) was successfully cleared.\n"},
		{ago: 40 * time.Minute, conn: "shop-db", cmd: "mysql -e 'SHOW PROCESSLIST'", decision: audit.Approved, by: "tui",
			justification: "Check for long-running queries behind the slow checkout", exit: exit(0), ms: 830,
			out: "Id\tUser\tHost\tdb\tCommand\tTime\tState\tInfo\n41\tshop\t10.0.0.12:51544\tshop\tQuery\t0\tstarting\tSHOW PROCESSLIST\n"},
		{ago: 31 * time.Minute, conn: "blog", cmd: "cat /var/www/blog/.env", decision: audit.Timeout, by: "timeout",
			justification: "Look up the mail settings"},
		{ago: 22 * time.Minute, conn: "shop-prod", cmd: "rm -rf /var/www/shop/var/cache/prod", decision: audit.Denied, by: "tui",
			justification: "The cache is stale after the deploy", note: "use bin/console cache:clear instead"},
		{ago: 12 * time.Minute, conn: "shop-prod", cmd: "df -h /var/www", decision: audit.Auto, exit: exit(0), ms: 388,
			out: "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        80G   51G   26G  67% /\n"},
		{ago: 8 * time.Minute, conn: "shop-prod", cmd: "tail -n 200 /var/www/shop/var/log/prod.log", decision: audit.Auto, exit: exit(0), ms: 517,
			justification: "Find the 500 errors on /checkout",
			out:           "[2026-10-03T09:41:02] request.CRITICAL: Uncaught PHP Exception Doctrine\\DBAL\\Exception\\ConnectionException: \"SQLSTATE[HY000] [2002] Connection refused\" at /var/www/shop/vendor/doctrine/dbal/src/Driver/API/MySQL/ExceptionConverter.php line 101\n"},
		{ago: 4 * time.Minute, conn: "shop-prod", cmd: "docker ps --format '{{.Names}}: {{.Status}}'", decision: audit.Auto, exit: exit(0), ms: 702,
			out: "shop-php-1: Up 3 days\nshop-nginx-1: Up 3 days\nshop-redis-1: Up 3 days\n"},
	}
	for _, e := range events {
		c := byName[e.conn]
		d := policy.Decide(c.Level(), cl.Classify(e.cmd))
		entry := audit.Entry{Time: now.Add(-e.ago), Connection: e.conn, AccessLevel: c.Level(), Command: e.cmd,
			Decision: e.decision, DecidedBy: e.by, Reasons: d.Reasons, Agent: agentName, Justification: e.justification,
			Note: e.note, ExitCode: e.exit, DurationMS: e.ms, Stdout: e.out}
		if e.decision == audit.Blocked {
			entry.AccessLevel, entry.Reasons = "", nil
			entry.Error = fmt.Sprintf("unknown connection %q. Use list_connections to see the connections you may use.", e.conn)
		}
		if e.by == "remembered" {
			entry.Reasons = append(entry.Reasons, "remembered approval until "+now.Add(7*time.Hour).Format("2006-01-02 15:04"))
		}
		must(audit.Append(entry))
	}
	fmt.Printf("seeded %d connections and %d audit entries\n", len(conns), len(events))
}

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "seed: "+format+"\n", a...)
	os.Exit(1)
}
