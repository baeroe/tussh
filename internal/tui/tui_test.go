package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

type harnessT struct {
	m        *Model
	kr       *secrets.MemKeyring
	clip     string
	connects []string
}

func newHarness(t *testing.T, tab Tab) *harnessT {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TUSSH_CONFIG_DIR", filepath.Join(dir, "config"))
	t.Setenv("TUSSH_STATE_DIR", filepath.Join(dir, "state"))
	h := &harnessT{kr: secrets.NewMem()}
	h.m = New(Options{
		Tab: tab, Keyring: h.kr, Bin: "/opt/bin/tussh", NoTick: true,
		Clipboard: func(s string) error { h.clip = s; return nil },
		Connect: func(c config.Connection) (*exec.Cmd, func(), error) {
			h.connects = append(h.connects, c.Name)
			return exec.Command("true"), func() {}, nil
		},
	})
	h.m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	return h
}

func (h *harnessT) key(keys ...string) {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyMsg{Type: tea.KeyShiftTab}
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "ctrl+s":
			msg = tea.KeyMsg{Type: tea.KeyCtrlS}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "right":
			msg = tea.KeyMsg{Type: tea.KeyRight}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		h.m.Update(msg)
	}
}

// focusField moves the form focus to field i.
func (h *harnessT) focusField(i int) {
	for n := 0; h.m.form.focus != i && n < numFields*2; n++ {
		h.key("tab")
	}
}

func (h *harnessT) typeIn(field int, text string) {
	h.focusField(field)
	h.key(text)
}

func TestCreatePasswordConnection(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("n")
	if h.m.form == nil {
		t.Fatal("form not open")
	}
	h.typeIn(fName, "shop-prod")
	h.typeIn(fGroup, "lulububu")
	h.typeIn(fHost, "shop.example.com")
	h.typeIn(fPort, "2222")
	h.typeIn(fUser, "deploy")
	h.focusField(fAuth)
	h.key("right") // key -> password
	if h.m.form.auth != config.AuthPassword {
		t.Fatal("auth not switched")
	}
	h.key("ctrl+s")
	if h.m.form == nil || !strings.Contains(h.m.form.err, "password") {
		t.Fatalf("password must be required, err=%q", h.m.form.err)
	}
	h.typeIn(fPassword, "s3cret!")
	h.focusField(fLevel)
	h.key("right") // none -> read-only
	h.typeIn(fTunnels, "mysql=3307:127.0.0.1:3306")
	h.key("ctrl+s")
	if h.m.form != nil {
		t.Fatalf("form still open: %s", h.m.form.err)
	}
	s, _ := config.Load()
	c, ok := s.ByName("shop-prod")
	if !ok || c.Port != 2222 || c.Auth != config.AuthPassword || !c.HasPassword || c.AccessLevel != config.LevelReadOnly || len(c.Tunnels) != 1 {
		t.Fatalf("saved: %+v", c)
	}
	if pw, _ := h.kr.Get(secrets.Account(c.ID, secrets.KindPassword)); pw != "s3cret!" {
		t.Fatalf("keyring: %q", pw)
	}
	data, _ := os.ReadFile(config.ConnectionsFile())
	if strings.Contains(string(data), "s3cret") {
		t.Fatal("password in connections.json")
	}
	if !strings.Contains(h.m.View(), "shop-prod") {
		t.Fatal("not listed")
	}
}

func TestNewConnectionDefaultsToNone(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.key("n")
	h.typeIn(fName, "box")
	h.typeIn(fHost, "10.0.0.5")
	h.key("ctrl+s")
	s, _ := config.Load()
	c, _ := s.ByName("box")
	if c.AccessLevel != config.LevelNone || c.Auth != config.AuthKey {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestCycleLevelEditDelete(t *testing.T) {
	h := newHarness(t, TabConnections)
	s, _ := config.Load()
	c, _ := s.Upsert(config.Connection{Name: "web", Host: "web.example", Auth: config.AuthKey, AccessLevel: config.LevelNone, HasPassphrase: true})
	s.Save()
	h.kr.Set(secrets.Account(c.ID, secrets.KindPassphrase), "pp")
	h.m.reload()
	h.key("l")
	s, _ = config.Load()
	if got, _ := s.ByName("web"); got.AccessLevel != config.LevelReadOnly {
		t.Fatalf("level after l: %s", got.AccessLevel)
	}
	// edit: empty passphrase keeps the stored one
	h.key("e")
	h.typeIn(fDescription, "edited")
	h.key("ctrl+s")
	s, _ = config.Load()
	got, _ := s.ByName("web")
	if got.Description != "edited" || !got.HasPassphrase {
		t.Fatalf("edit: %+v", got)
	}
	if pp, _ := h.kr.Get(secrets.Account(c.ID, secrets.KindPassphrase)); pp != "pp" {
		t.Fatal("passphrase lost on edit")
	}
	// delete needs confirmation
	h.key("x", "n")
	if s, _ := config.Load(); len(s.Connections) != 1 {
		t.Fatal("deleted without confirmation")
	}
	h.key("x", "y")
	if s, _ := config.Load(); len(s.Connections) != 0 {
		t.Fatal("not deleted")
	}
	if _, err := h.kr.Get(secrets.Account(c.ID, secrets.KindPassphrase)); err == nil {
		t.Fatal("secret not removed with the connection")
	}
}

func TestEnterConnects(t *testing.T) {
	h := newHarness(t, TabConnections)
	s, _ := config.Load()
	s.Upsert(config.Connection{Name: "web", Host: "web.example", Auth: config.AuthKey, AccessLevel: config.LevelNone})
	s.Save()
	h.m.reload()
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || len(h.connects) != 1 || h.connects[0] != "web" {
		t.Fatalf("connect: %v %v", cmd, h.connects)
	}
}

func submit(t *testing.T, command string) *approval.Request {
	t.Helper()
	r := &approval.Request{Connection: "web", Command: command, Reasons: []string{"delete: deletes files"},
		Agent: "claude-code", Justification: "cleanup", Expires: time.Now().Add(time.Minute), AccessLevel: "trusted"}
	if err := approval.Open().Submit(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestModalApprove(t *testing.T) {
	h := newHarness(t, TabConnections)
	r := submit(t, "rm -rf /tmp/cache")
	h.m.Update(tickMsg(time.Now()))
	if h.m.modal == nil || h.m.modal.ID != r.ID {
		t.Fatal("no modal for new request")
	}
	v := h.m.View()
	for _, want := range []string{"Agent approval request", "rm -rf /tmp/cache", "claude-code", "cleanup", "deletes files"} {
		if !strings.Contains(v, want) {
			t.Errorf("modal misses %q", want)
		}
	}
	h.key("a")
	d, err := approval.Open().Decision(r.ID)
	if err != nil || d.Decision != approval.Approved || d.By != "tui" {
		t.Fatalf("decision: %+v %v", d, err)
	}
	if h.m.modal != nil {
		t.Fatal("modal still open")
	}
	// the same request does not pop up again
	h.m.Update(tickMsg(time.Now()))
	if h.m.modal != nil {
		t.Fatal("decided request popped up again")
	}
}

func TestModalLaterThenDenyInAlerts(t *testing.T) {
	h := newHarness(t, TabConnections)
	r := submit(t, "systemctl stop nginx")
	h.m.Update(tickMsg(time.Now()))
	h.key("esc")
	if h.m.modal != nil || h.m.tab != TabAlerts {
		t.Fatal("esc should close the modal and show Alerts")
	}
	if !strings.Contains(h.m.View(), "Alerts (1)") {
		t.Fatal("badge missing")
	}
	h.key("d")
	d, _ := approval.Open().Decision(r.ID)
	if d == nil || d.Decision != approval.Denied {
		t.Fatalf("deny: %+v", d)
	}
}

func TestAlertsTabStartAndExpiredRequest(t *testing.T) {
	r := func() *approval.Request {
		dir := t.TempDir()
		t.Setenv("TUSSH_STATE_DIR", filepath.Join(dir, "state"))
		return submit(t, "docker system prune -af")
	}()
	h := &harnessT{kr: secrets.NewMem()}
	t.Setenv("TUSSH_CONFIG_DIR", t.TempDir())
	h.m = New(Options{Tab: TabAlerts, Keyring: h.kr, NoTick: true, Clipboard: func(string) error { return nil }})
	if h.m.tab != TabAlerts || len(h.m.pending) != 1 {
		t.Fatal("alerts tab should list the pending request")
	}
	// decided elsewhere (e.g. timeout) -> approving reports it is no longer pending
	approval.Open().Resolve(r.ID, approval.Timeout, "timeout", "")
	h.key("a")
	if !h.m.statusErr || !strings.Contains(h.m.status, "no longer pending") {
		t.Fatalf("status: %q", h.m.status)
	}
}

func TestSetupCopiesSnippet(t *testing.T) {
	h := newHarness(t, TabSetup)
	h.key("enter")
	if h.clip != "claude mcp add --scope user tussh -- /opt/bin/tussh mcp" {
		t.Fatalf("clipboard: %q", h.clip)
	}
	if !strings.Contains(h.m.View(), "Gemini CLI") {
		t.Fatal("setup view")
	}
}

func TestTabSwitchingAndViews(t *testing.T) {
	h := newHarness(t, TabConnections)
	for i := 0; i < int(numTabs); i++ {
		v := h.m.View()
		if !strings.Contains(v, tabNames[h.m.tab]) {
			t.Fatalf("tab %d view", i)
		}
		h.key("tab")
	}
	if h.m.tab != TabConnections {
		t.Fatal("tab cycle")
	}
	h.key("4")
	if h.m.tab != TabHistory {
		t.Fatal("number key")
	}
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should quit")
	}
}

func TestImportFromSSHConfig(t *testing.T) {
	h := newHarness(t, TabConnections)
	cfg := filepath.Join(t.TempDir(), "ssh_config")
	os.WriteFile(cfg, []byte("Host alpha\n  HostName 10.1.1.1\n  User root\n  Port 2200\nHost *\n  ServerAliveInterval 30\nHost beta\n  HostName beta.example\n"), 0o600)
	h.m.opts.SSHConfig = cfg
	h.key("i")
	if h.m.imp == nil || len(h.m.imp.hosts) != 2 {
		t.Fatalf("import view: %+v", h.m.imp)
	}
	h.key("space", "enter")
	s, _ := config.Load()
	c, ok := s.ByName("alpha")
	if !ok || c.Host != "10.1.1.1" || c.User != "root" || c.Port != 2200 || c.AccessLevel != config.LevelNone {
		t.Fatalf("imported: %+v (%s)", c, h.m.status)
	}
	if _, ok := s.ByName("beta"); ok {
		t.Fatal("unselected host imported")
	}
}

func TestParseTunnels(t *testing.T) {
	ts, err := parseTunnels("db=3307:127.0.0.1:3306, web=0.0.0.0:8080:localhost:80")
	if err != nil || len(ts) != 2 || ts[1].Bind != "0.0.0.0" || ts[0].Spec() != "127.0.0.1:3307:127.0.0.1:3306" {
		t.Fatalf("%+v %v", ts, err)
	}
	if formatTunnels(ts) != "db=3307:127.0.0.1:3306, web=0.0.0.0:8080:localhost:80" {
		t.Fatal(formatTunnels(ts))
	}
	for _, bad := range []string{"x", "a=1:2", "a=x:h:1"} {
		if _, err := parseTunnels(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExitWhenDone(t *testing.T) {
	h := newHarness(t, TabAlerts)
	h.m.opts.ExitWhenDone = true
	r := submit(t, "reboot")
	h.m.Update(tickMsg(time.Now()))
	if h.m.quitting {
		t.Fatal("quit while a request is pending")
	}
	h.key("a")
	_ = r
	h.m.Update(tickMsg(time.Now()))
	if !h.m.quitting {
		t.Fatal("should quit after the last request")
	}
}
