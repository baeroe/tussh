package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
)

func addConns(t *testing.T, h *harnessT, conns ...config.Connection) map[string]config.Connection {
	t.Helper()
	s, _ := config.Load()
	out := map[string]config.Connection{}
	for _, c := range conns {
		if c.Auth == "" {
			c.Auth = config.AuthKey
		}
		if c.AccessLevel == "" {
			c.AccessLevel = config.LevelNone
		}
		c, err := s.Upsert(c)
		if err != nil {
			t.Fatal(err)
		}
		out[c.Name] = c
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	h.m.reload()
	return out
}

func names(h *harnessT) string {
	var n []string
	for _, c := range h.m.rows {
		n = append(n, c.Name)
	}
	return strings.Join(n, ",")
}

func touch(id string, ago time.Duration) {
	config.TouchUsed(id)
	t := time.Now().Add(-ago)
	os.Chtimes(filepath.Join(config.StateDir(), "used", id), t, t)
}

func TestSortFavoritesThenLastUsedThenName(t *testing.T) {
	h := newHarness(t, TabConnections)
	cs := addConns(t, h, config.Connection{Name: "alpha", Host: "a.example"}, config.Connection{Name: "bravo", Host: "b.example"},
		config.Connection{Name: "charlie", Host: "c.example"}, config.Connection{Name: "delta", Host: "d.example", Favorite: true},
		config.Connection{Name: "echo", Host: "e.example"})
	touch(cs["charlie"].ID, time.Hour)
	touch(cs["echo"].ID, time.Minute)
	h.m.reload()
	if got := names(h); got != "delta,echo,charlie,alpha,bravo" {
		t.Fatalf("order: %s", got)
	}
	// f toggles a favorite and keeps it selected; it is saved
	h.m.cursor[TabConnections] = 3 // alpha
	h.key("f")
	if got := names(h); got != "alpha,delta,echo,charlie,bravo" {
		t.Fatalf("after favorite: %s", got)
	}
	if c, _ := h.m.selectedConnection(); c.Name != "alpha" {
		t.Fatalf("selection moved to %s", c.Name)
	}
	s, _ := config.Load()
	if c, _ := s.ByName("alpha"); !c.Favorite {
		t.Fatal("favorite not saved")
	}
	if !strings.Contains(h.m.View(), "★") || !strings.Contains(h.m.View(), "────") {
		t.Fatal("favorite star or divider missing")
	}
	h.key("f")
	if s, _ := config.Load(); func() bool { c, _ := s.ByName("alpha"); return c.Favorite }() {
		t.Fatal("favorite not removed")
	}
	// connecting records the last use and moves the connection up
	h.m.cursor[TabConnections] = 4
	sel, _ := h.m.selectedConnection()
	h.key("enter")
	if !strings.HasPrefix(names(h), "delta,"+sel.Name+",") {
		t.Fatalf("last used not first after favorites: %s", names(h))
	}
}

func TestSearchFiltersAndOwnsKeys(t *testing.T) {
	h := newHarness(t, TabConnections)
	addConns(t, h, config.Connection{Name: "shop-prod", Host: "10.0.0.1", User: "deploy", Tags: []string{"lulububu"}},
		config.Connection{Name: "homelab", Host: "nas.local", Description: "Synology"},
		config.Connection{Name: "client-web", Host: "web.client.example"})
	h.key("/")
	if !h.m.searching {
		t.Fatal("search not open")
	}
	h.key("l", "u", "l", "u")
	if got := names(h); got != "shop-prod" {
		t.Fatalf("tag search: %s", got)
	}
	// tab, digits and q go into the search, they do not switch views or quit
	h.key("tab", "1", "q")
	if h.m.tab != TabConnections || h.m.quitting || h.m.query[TabConnections] != "lulu1q" {
		t.Fatalf("keys leaked: tab=%v query=%q", h.m.tab, h.m.query[TabConnections])
	}
	h.key("esc")
	if h.m.searching || h.m.query[TabConnections] != "" || len(h.m.rows) != 3 {
		t.Fatal("esc must clear the search")
	}
	for q, want := range map[string]string{"synology": "homelab", "nas": "homelab", "deploy": "shop-prod", "cweb": "client-web", "hmlb": "homelab"} {
		h.key("/")
		h.key(q, "enter")
		if got := names(h); got != want {
			t.Errorf("search %q: %s", q, got)
		}
		h.key("esc")
	}
}

func TestTabInFormMovesFieldsOnly(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("n")
	before := h.m.form.focus
	h.key("tab")
	if h.m.tab != TabConnections || h.m.form == nil || h.m.form.focus == before {
		t.Fatal("tab must move to the next field and keep the view")
	}
	h.key("shift+tab")
	if h.m.form.focus != before {
		t.Fatal("shift+tab")
	}
	h.key("2", "q") // typed into the name field
	if h.m.tab != TabConnections || h.m.quitting || h.m.form.inputs[fName].Value() != "2q" {
		t.Fatalf("keys leaked: %q", h.m.form.inputs[fName].Value())
	}
}

func TestPortPlaceholderAndSections(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("n")
	v := ansi.Strip(h.m.View())
	if !regexp.MustCompile(`Port\s+22\s`).MatchString(v) {
		t.Fatal("port placeholder must show 22")
	}
	for _, want := range []string{"Connection", "Authentication", "Agent access", "Tunnels", "Tags", "ctrl+t"} {
		if !strings.Contains(v, want) {
			t.Errorf("form misses %q", want)
		}
	}
	if strings.Contains(v, "Group") {
		t.Fatal("group field still present")
	}
}

func TestFormTagsAndTestConnection(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("n")
	h.typeIn(fName, "web")
	h.typeIn(fHost, "web.example")
	h.typeIn(fTags, "prod, Shop, prod")
	h.focusField(fAuth)
	h.key("right")
	h.typeIn(fPassword, "wrong")
	h.key("ctrl+t")
	if !h.m.form.testing {
		t.Fatal("test not started")
	}
	h.run(h.lastCmd)
	if h.m.form.testOK || !strings.Contains(ansi.Strip(h.m.View()), "Permission denied") {
		t.Fatalf("failed test not shown: %q", h.m.form.testResult)
	}
	if len(h.tested) != 1 || h.tested[0].Host != "web.example" || h.tested[0].Auth != config.AuthPassword {
		t.Fatalf("tested: %+v", h.tested)
	}
	if s, _ := config.Load(); len(s.Connections) != 0 {
		t.Fatal("test must not save")
	}
	h.typeIn(fPassword, "x")
	h.key("ctrl+t")
	h.run(h.lastCmd)
	if !h.m.form.testOK {
		t.Fatal("ok test not shown")
	}
	h.key("ctrl+s")
	s, _ := config.Load()
	c, ok := s.ByName("web")
	if !ok || strings.Join(c.Tags, ",") != "prod,Shop" {
		t.Fatalf("tags: %+v", c)
	}
}

func TestReachability(t *testing.T) {
	h := newHarness(t, TabConnections)
	cs := addConns(t, h, config.Connection{Name: "up", Host: "up.example"}, config.Connection{Name: "down", Host: "down.example"})
	h.down["down.example"] = true
	h.key("r")
	if h.m.reach[cs["up"].ID].state != reachChecking {
		t.Fatal("not checking")
	}
	if !strings.Contains(h.m.View(), "◌") {
		t.Fatal("checking dot missing")
	}
	h.run(h.lastCmd)
	if h.m.reach[cs["up"].ID].state != reachUp || h.m.reach[cs["down"].ID].state != reachDown {
		t.Fatalf("reach: %+v", h.m.reach)
	}
	h.m.selectByID(cs["down"].ID)
	if v := ansi.Strip(h.m.View()); !strings.Contains(v, "unreachable · unknown host") {
		t.Fatal("detail misses reachability")
	}
	if len(h.probes) != 2 {
		t.Fatalf("probes: %v", h.probes)
	}
}

func submitFor(t *testing.T, c config.Connection, command string) *approval.Request {
	t.Helper()
	r := &approval.Request{Connection: c.Name, ConnectionID: c.ID, Command: command, Reasons: []string{"system: restarts a service"},
		Agent: "claude-code", Created: time.Now(), Expires: time.Now().Add(time.Minute), AccessLevel: c.AccessLevel}
	if err := approval.Open().Submit(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDenyWithNote(t *testing.T) {
	h := newHarness(t, TabConnections)
	cs := addConns(t, h, config.Connection{Name: "web", Host: "web.example", AccessLevel: config.LevelTrusted})
	r := submitFor(t, cs["web"], "systemctl restart nginx")
	h.m.Update(tickMsg(time.Now()))
	if h.m.modal == nil {
		t.Fatal("no popup")
	}
	h.key("n")
	if h.m.denyNote == nil {
		t.Fatal("note input not open")
	}
	h.key("tab", "1") // stays in the note
	h.key("esc")
	if h.m.denyNote != nil || h.m.modal == nil {
		t.Fatal("esc must cancel the note only")
	}
	if d, _ := approval.Open().Decision(r.ID); d != nil {
		t.Fatal("decided by cancelling the note")
	}
	h.key("n")
	h.key("use reload, not restart")
	h.key("enter")
	d, err := approval.Open().Decision(r.ID)
	if err != nil || d.Decision != approval.Denied || d.Note != "use reload, not restart" {
		t.Fatalf("decision: %+v %v", d, err)
	}
	if h.m.modal != nil || h.m.denyNote != nil {
		t.Fatal("popup still open")
	}
}

func TestApproveAndRememberAndRevoke(t *testing.T) {
	h := newHarness(t, TabConnections)
	cs := addConns(t, h, config.Connection{Name: "web", Host: "web.example", AccessLevel: config.LevelApproveEach,
		Tunnels: []config.Tunnel{{Name: "db", Local: 3307, RemoteHost: "127.0.0.1", RemotePort: 3306}}})
	r := submitFor(t, cs["web"], "systemctl restart nginx")
	h.key("3")
	h.key("m")
	d, _ := approval.Open().Decision(r.ID)
	if d == nil || d.Decision != approval.Approved {
		t.Fatalf("decision: %+v", d)
	}
	e, ok := allow.Match(cs["web"].ID, "systemctl restart nginx")
	if !ok || time.Until(e.Expires) < 7*time.Hour || time.Until(e.Expires) > 9*time.Hour {
		t.Fatalf("remembered entry: %+v %v", e, ok)
	}
	h.key("1")
	v := ansi.Strip(h.m.View())
	if !strings.Contains(v, "Remembered commands") || !strings.Contains(v, "systemctl restart nginx") {
		t.Fatal("detail misses the remembered command")
	}
	h.key("R")
	if !h.m.detailFocus || h.m.detailCursor != 1 {
		t.Fatalf("R must select the remembered command (cursor %d)", h.m.detailCursor)
	}
	h.key("enter")
	if _, ok := allow.Match(cs["web"].ID, "systemctl restart nginx"); ok {
		t.Fatal("not revoked")
	}
	if !h.m.detailFocus || h.m.detailCursor != 0 {
		t.Fatal("the cursor should move to the remaining tunnel")
	}
}

func TestRememberUsesSettingsTTL(t *testing.T) {
	h := newHarness(t, TabAlerts)
	cs := addConns(t, h, config.Connection{Name: "web", Host: "web.example", AccessLevel: config.LevelTrusted})
	os.MkdirAll(config.ConfigDir(), 0o700)
	os.WriteFile(config.SettingsFile(), []byte(`{"remember_ttl_hours": 1}`), 0o600)
	submitFor(t, cs["web"], "reboot")
	h.m.refreshPending(false)
	h.key("m")
	e, ok := allow.Match(cs["web"].ID, "reboot")
	if !ok || time.Until(e.Expires) > time.Hour {
		t.Fatalf("ttl: %+v", e)
	}
}

func writeAudit(t *testing.T, entries ...audit.Entry) {
	for _, e := range entries {
		if err := audit.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHistoryFiltersAndDetail(t *testing.T) {
	h := newHarness(t, TabConnections)
	zero, one := 0, 1
	writeAudit(t,
		audit.Entry{Connection: "web", Command: "uptime", Decision: audit.Auto, ExitCode: &zero, Stdout: "up 3 days\tload 0.1\n"},
		audit.Entry{Connection: "db", Command: "rm -rf /data", Decision: audit.Denied, Note: "never on db"},
		audit.Entry{Connection: "web", Command: "make deploy", Decision: audit.Approved, ExitCode: &one, Stderr: "make: *** failed\x1b[31m"},
	)
	h.key("4")
	if len(h.m.filteredHistory()) != 3 {
		t.Fatal("history not loaded")
	}
	h.key("c") // first connection alphabetically: db
	if f := h.m.filteredHistory(); len(f) != 1 || f[0].Connection != "db" {
		t.Fatalf("conn filter: %+v", f)
	}
	if v := ansi.Strip(h.m.View()); !strings.Contains(v, "never on db") || !strings.Contains(v, "conn:db") {
		t.Fatal("detail misses the note or the filter chip")
	}
	h.key("c", "d") // web, then decision auto
	if f := h.m.filteredHistory(); len(f) != 1 || f[0].Command != "uptime" {
		t.Fatalf("decision filter: %+v", f)
	}
	v := h.m.View()
	if !strings.Contains(ansi.Strip(v), "up 3 days    load 0.1") {
		t.Fatal("output missing or tab not expanded")
	}
	h.key("esc")
	h.key("/")
	h.key("deploy", "enter")
	f := h.m.filteredHistory()
	if len(f) != 1 || f[0].Command != "make deploy" {
		t.Fatalf("search: %+v", f)
	}
	if strings.Contains(h.m.View(), "\x1b[31m") {
		t.Fatal("escape sequence from command output reached the screen")
	}
}

func TestSetupShowsRegistration(t *testing.T) {
	h := newHarness(t, TabConnections)
	os.WriteFile(filepath.Join(h.m.opts.Home, ".claude.json"), []byte(`{"mcpServers":{"tussh":{"command":"x"}}}`), 0o600)
	h.key("5")
	v := ansi.Strip(h.m.View())
	if !strings.Contains(v, "✓ registered") || !strings.Contains(v, "✓ Claude Code") || !strings.Contains(v, "· Cursor") {
		t.Fatal("registration state missing")
	}
	h.key("down")
	if !strings.Contains(ansi.Strip(h.m.View()), "not registered") {
		t.Fatal("codex should be not registered")
	}
}

func TestDetailTunnelSelection(t *testing.T) {
	h := newHarness(t, TabConnections)
	addConns(t, h, config.Connection{Name: "web", Host: "web.example", Tunnels: []config.Tunnel{
		{Name: "db", Local: 3307, RemoteHost: "127.0.0.1", RemotePort: 3306}, {Name: "redis", Local: 6380, RemoteHost: "localhost", RemotePort: 6379}}})
	h.key("t")
	if !h.m.detailFocus {
		t.Fatal("t must focus the tunnels")
	}
	h.key("down", "down")
	if h.m.detailCursor != 1 {
		t.Fatal("cursor")
	}
	h.key("esc")
	if h.m.detailFocus {
		t.Fatal("esc")
	}
}

func TestHelpOverlay(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("?")
	if !h.m.help || !strings.Contains(h.m.View(), "approve & remember") {
		t.Fatal("help")
	}
	h.key("?")
	if h.m.help {
		t.Fatal("help not closed")
	}
}

// TestLayoutAlignment renders every view with colors on and checks that each screen has exactly the terminal
// size and that the columns of the selected row line up with the others.
func TestLayoutAlignment(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	h := newHarness(t, TabConnections)
	cs := addConns(t, h,
		config.Connection{Name: "shop-prod", Host: "10.0.0.1", User: "deploy", AccessLevel: config.LevelApproveEach, Tags: []string{"prod"},
			Tunnels: []config.Tunnel{{Name: "db", Local: 3307, RemoteHost: "127.0.0.1", RemotePort: 3306}}},
		config.Connection{Name: "homelab", Host: "nas.local", AccessLevel: config.LevelReadOnly, Favorite: true},
		config.Connection{Name: "trusted-box", Host: "t.example", AccessLevel: config.LevelTrusted},
		config.Connection{Name: "hidden", Host: "h.example"})
	zero := 0
	writeAudit(t, audit.Entry{Connection: "shop-prod", Command: "ls\t-la", Decision: audit.Approved, ExitCode: &zero},
		audit.Entry{Connection: "homelab", Command: "df -h", Decision: audit.Timeout})
	submitFor(t, cs["shop-prod"], "sudo systemctl restart nginx && rm -rf /var/cache/nginx/*")
	h.m.refreshPending(false)
	h.m.refreshHistory()
	for _, size := range [][2]int{{110, 32}, {80, 24}, {140, 40}} {
		h.m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for _, keys := range [][]string{{"1"}, {"1", "down"}, {"1", "e"}, {"esc", "?"}, {"?", "2"}, {"3"}, {"4"}, {"5"}} {
			h.key(keys...)
			v := h.m.View()
			lines := strings.Split(v, "\n")
			if len(lines) != size[1] {
				t.Fatalf("%v %v: %d lines", size, keys, len(lines))
			}
			for i, l := range lines {
				if w := ansi.StringWidth(l); w > size[0] {
					t.Fatalf("%v %v: line %d is %d wide: %q", size, keys, i, w, ansi.Strip(l))
				}
				if strings.ContainsRune(ansi.Strip(l), '\t') {
					t.Fatalf("tab character on screen: %q", l)
				}
			}
			if keys[len(keys)-1] == "down" || keys[0] == "1" && len(keys) == 1 {
				checkBadgeColumn(t, lines)
			}
		}
		h.key("esc")
	}
}

// checkBadgeColumn: in the connection list every row's level badge starts at the same column.
func checkBadgeColumn(t *testing.T, lines []string) {
	t.Helper()
	col := -1
	for _, l := range lines {
		p := ansi.Strip(l)
		if strings.Contains(p, "Agent access") {
			continue
		}
		for _, b := range []string{"👀 read-only", "✋ approve", "✓  trusted", "⛔ none"} {
			i := strings.Index(p, b)
			if i < 0 {
				continue
			}
			c := ansi.StringWidth(p[:i])
			if col >= 0 && c != col {
				t.Fatalf("badge column %d != %d in %q", c, col, p)
			}
			col = c
		}
	}
	if col < 0 {
		t.Fatal("no badges found")
	}
}
