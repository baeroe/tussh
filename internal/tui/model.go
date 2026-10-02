// Package tui is the tussh terminal UI (Bubble Tea): connections, tunnels, alerts (approvals), history, setup.
package tui

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/harness"
	"github.com/baeroe/tussh/internal/secrets"
	"github.com/baeroe/tussh/internal/sshconfig"
	"github.com/baeroe/tussh/internal/sshrun"
)

// Tab identifies a view.
type Tab int

const (
	TabConnections Tab = iota
	TabTunnels
	TabAlerts
	TabHistory
	TabSetup
	numTabs
)

var tabNames = []string{"Connections", "Tunnels", "Alerts", "History", "Setup"}

// Options configure the model (tests inject fakes).
type Options struct {
	Tab       Tab
	Keyring   secrets.Keyring
	Queue     *approval.Queue
	Bin       string                  // absolute tussh path for the Setup snippets
	Clipboard func(text string) error // default pbcopy / wl-copy / xclip
	// Connect returns the command for an interactive session (default sshrun.InteractiveCommand).
	Connect   func(c config.Connection) (*exec.Cmd, func(), error)
	SSHConfig string // ssh config to import from (default ~/.ssh/config)
	NoTick    bool   // tests drive ticks manually
	// ExitWhenDone quits once requests were shown and none are pending any more (herdr alerts popup).
	ExitWhenDone bool
}

type tickMsg time.Time

type sshDoneMsg struct {
	name string
	err  error
}

type tunnelDoneMsg struct {
	key string
	err error
	up  bool
}

// Model is the root Bubble Tea model.
type Model struct {
	opts    Options
	tab     Tab
	width   int
	height  int
	store   *config.Store
	loadErr error
	rules   *classify.Classifier

	cursor [numTabs]int

	pending []approval.Request
	seen    map[string]bool
	modal   *approval.Request

	history     []audit.Entry
	historyOpen bool

	tunnelState map[string]bool
	tunnelBusy  map[string]bool

	snippets []harness.Snippet

	form    *connForm
	confirm *config.Connection // pending delete
	imp     *importView

	status    string
	statusErr bool
	quitting  bool
}

// New creates the model.
func New(opts Options) *Model {
	if opts.Keyring == nil {
		opts.Keyring = secrets.Open()
	}
	if opts.Queue == nil {
		opts.Queue = approval.Open()
	}
	if opts.Bin == "" {
		opts.Bin = sshrun.Self()
	}
	if opts.Clipboard == nil {
		opts.Clipboard = copyToClipboard
	}
	if opts.Connect == nil {
		opts.Connect = sshrun.InteractiveCommand
	}
	if opts.SSHConfig == "" {
		opts.SSHConfig = sshconfig.DefaultPath()
	}
	m := &Model{opts: opts, tab: opts.Tab, seen: map[string]bool{}, tunnelState: map[string]bool{}, tunnelBusy: map[string]bool{}}
	m.snippets = harness.Snippets(opts.Bin)
	m.reload()
	m.refreshPending(false)
	return m
}

// Init starts the refresh ticker.
func (m *Model) Init() tea.Cmd {
	approval.Heartbeat()
	if m.opts.NoTick {
		return nil
	}
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) reload() {
	s, err := config.Load()
	m.loadErr = err
	if err != nil {
		s = &config.Store{Version: 1}
	}
	m.store = s
	m.rules = classify.LoadRules(config.RulesFile())
	m.refreshTunnels()
	m.clampCursors()
}

func (m *Model) refreshTunnels() {
	for _, c := range m.store.Connections {
		for _, t := range c.Tunnels {
			m.tunnelState[tunnelKey(c, t)] = sshrun.Status(c, t).Running
		}
	}
}

func (m *Model) refreshHistory() {
	h, _ := audit.Read(500)
	m.history = h
	m.clampCursors()
}

// refreshPending reloads the queue; with popup it opens the modal for a request not seen before.
func (m *Model) refreshPending(popup bool) {
	m.pending = m.opts.Queue.Pending()
	ids := map[string]bool{}
	for _, r := range m.pending {
		ids[r.ID] = true
		if !m.seen[r.ID] {
			m.seen[r.ID] = true
			if popup && m.modal == nil {
				r := r
				m.modal = &r
			}
		}
	}
	if m.modal != nil && !ids[m.modal.ID] {
		m.modal = nil // decided elsewhere or timed out
	}
	m.clampCursors()
}

func tunnelKey(c config.Connection, t config.Tunnel) string { return c.ID + "/" + t.Name }

type tunnelRow struct {
	conn   config.Connection
	tunnel config.Tunnel
}

func (m *Model) tunnelRows() []tunnelRow {
	var rows []tunnelRow
	for _, c := range m.store.Connections {
		for _, t := range c.Tunnels {
			rows = append(rows, tunnelRow{c, t})
		}
	}
	return rows
}

func (m *Model) rowCount(t Tab) int {
	switch t {
	case TabConnections:
		return len(m.store.Connections)
	case TabTunnels:
		return len(m.tunnelRows())
	case TabAlerts:
		return len(m.pending)
	case TabHistory:
		return len(m.history)
	case TabSetup:
		return len(m.snippets)
	}
	return 0
}

func (m *Model) clampCursors() {
	for t := Tab(0); t < numTabs; t++ {
		n := m.rowCount(t)
		if m.cursor[t] >= n {
			m.cursor[t] = n - 1
		}
		if m.cursor[t] < 0 {
			m.cursor[t] = 0
		}
	}
}

func (m *Model) flash(format string, a ...any) {
	m.status, m.statusErr = fmt.Sprintf(format, a...), false
}

func (m *Model) flashErr(format string, a ...any) {
	m.status, m.statusErr = fmt.Sprintf(format, a...), true
}

// Update handles messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		approval.Heartbeat()
		m.refreshPending(true)
		if m.opts.ExitWhenDone && len(m.seen) > 0 && len(m.pending) == 0 && m.form == nil && m.imp == nil {
			return m.quit()
		}
		if m.tab == TabHistory {
			m.refreshHistory()
		}
		if m.tab == TabTunnels && time.Time(msg).Second()%2 == 0 {
			m.refreshTunnels()
		}
		return m, tick()
	case sshDoneMsg:
		m.reload()
		if msg.err != nil {
			m.flashErr("ssh %s: %v", msg.name, msg.err)
		} else {
			m.flash("session to %s closed", msg.name)
		}
		return m, nil
	case tunnelDoneMsg:
		delete(m.tunnelBusy, msg.key)
		m.refreshTunnels()
		if msg.err != nil {
			m.flashErr("%v", msg.err)
		} else if msg.up {
			m.flash("tunnel started")
		} else {
			m.flash("tunnel stopped")
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		return m.quit()
	}
	if m.modal != nil {
		return m.modalKey(key)
	}
	if m.form != nil {
		return m.formKey(k)
	}
	if m.imp != nil {
		return m.importKey(key)
	}
	if m.confirm != nil {
		c := *m.confirm
		m.confirm = nil
		if key == "y" || key == "Y" {
			m.deleteConnection(c)
		} else {
			m.flash("delete cancelled")
		}
		return m, nil
	}
	switch key {
	case "q":
		return m.quit()
	case "tab", "right":
		m.switchTab((m.tab + 1) % numTabs)
		return m, nil
	case "shift+tab", "left":
		m.switchTab((m.tab + numTabs - 1) % numTabs)
		return m, nil
	case "1", "2", "3", "4", "5":
		m.switchTab(Tab(key[0] - '1'))
		return m, nil
	case "up", "k", "ctrl+p":
		if m.cursor[m.tab] > 0 {
			m.cursor[m.tab]--
		}
		return m, nil
	case "down", "j", "ctrl+n":
		if m.cursor[m.tab] < m.rowCount(m.tab)-1 {
			m.cursor[m.tab]++
		}
		return m, nil
	}
	switch m.tab {
	case TabConnections:
		return m.connectionsKey(key)
	case TabTunnels:
		return m.tunnelsKey(key)
	case TabAlerts:
		return m.alertsKey(key)
	case TabHistory:
		if key == "enter" {
			m.historyOpen = !m.historyOpen
		}
	case TabSetup:
		if key == "enter" && len(m.snippets) > 0 {
			s := m.snippets[m.cursor[TabSetup]]
			if err := m.opts.Clipboard(s.Text); err != nil {
				m.flashErr("copy failed: %v", err)
			} else {
				m.flash("copied: %s", s.Name)
			}
		}
	}
	return m, nil
}

func (m *Model) quit() (tea.Model, tea.Cmd) {
	m.quitting = true
	approval.ClearHeartbeat()
	return m, tea.Quit
}

func (m *Model) switchTab(t Tab) {
	m.tab = t
	m.status = ""
	switch t {
	case TabHistory:
		m.refreshHistory()
	case TabTunnels:
		m.refreshTunnels()
	case TabAlerts:
		m.refreshPending(false)
	}
}

func (m *Model) selectedConnection() (config.Connection, bool) {
	if len(m.store.Connections) == 0 {
		return config.Connection{}, false
	}
	return m.store.Connections[m.cursor[TabConnections]], true
}

func (m *Model) connectionsKey(key string) (tea.Model, tea.Cmd) {
	if m.loadErr != nil && key != "enter" {
		m.flashErr("connections.json is invalid, fix it first: %v", m.loadErr)
		return m, nil
	}
	switch key {
	case "n", "a":
		m.form = newForm(nil)
	case "e":
		if c, ok := m.selectedConnection(); ok {
			m.form = newForm(&c)
		}
	case "x", "delete", "D":
		if c, ok := m.selectedConnection(); ok {
			m.confirm = &c
		}
	case "l":
		if c, ok := m.selectedConnection(); ok {
			c.AccessLevel = nextLevel(c.Level())
			if _, err := m.store.Upsert(c); err != nil {
				m.flashErr("%v", err)
			} else if err := m.store.Save(); err != nil {
				m.flashErr("save failed: %v", err)
			} else {
				m.flash("%s: agent access %s", c.Name, c.AccessLevel)
			}
			m.selectByID(c.ID)
		}
	case "i":
		m.imp = newImportView(m.opts.SSHConfig, m.store)
	case "enter":
		c, ok := m.selectedConnection()
		if !ok {
			return m, nil
		}
		cmd, cleanup, err := m.opts.Connect(c)
		if err != nil {
			m.flashErr("%v", err)
			return m, nil
		}
		name := c.Name
		return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
			cleanup()
			return sshDoneMsg{name: name, err: err}
		})
	}
	return m, nil
}

func nextLevel(l string) string {
	for i, x := range config.Levels {
		if x == l {
			return config.Levels[(i+1)%len(config.Levels)]
		}
	}
	return config.LevelNone
}

func (m *Model) selectByID(id string) {
	for i, c := range m.store.Connections {
		if c.ID == id {
			m.cursor[TabConnections] = i
		}
	}
}

func (m *Model) deleteConnection(c config.Connection) {
	for _, t := range c.Tunnels {
		sshrun.StopTunnel(c, t)
	}
	_ = m.opts.Keyring.Delete(secrets.Account(c.ID, secrets.KindPassword))
	_ = m.opts.Keyring.Delete(secrets.Account(c.ID, secrets.KindPassphrase))
	m.store.Delete(c.ID)
	if err := m.store.Save(); err != nil {
		m.flashErr("save failed: %v", err)
		return
	}
	m.clampCursors()
	m.flash("deleted %s", c.Name)
}

func (m *Model) tunnelsKey(key string) (tea.Model, tea.Cmd) {
	rows := m.tunnelRows()
	if key != "enter" || len(rows) == 0 {
		return m, nil
	}
	r := rows[m.cursor[TabTunnels]]
	k := tunnelKey(r.conn, r.tunnel)
	if m.tunnelBusy[k] {
		return m, nil
	}
	m.tunnelBusy[k] = true
	running := m.tunnelState[k]
	if running {
		m.flash("stopping %s ...", r.tunnel.Name)
	} else {
		m.flash("starting %s ...", r.tunnel.Name)
	}
	return m, func() tea.Msg {
		if running {
			sshrun.StopTunnel(r.conn, r.tunnel)
			return tunnelDoneMsg{key: k}
		}
		_, err := sshrun.StartTunnel(r.conn, r.tunnel, 15*time.Second)
		return tunnelDoneMsg{key: k, err: err, up: err == nil}
	}
}

func (m *Model) resolve(r approval.Request, decision string) {
	err := m.opts.Queue.Resolve(r.ID, decision, "tui", "")
	switch {
	case err == nil:
		m.flash("%s: %s on %s", decision, short(r.Command, 50), r.Connection)
	case err == approval.ErrAlreadyDecided || err == approval.ErrUnknown:
		m.flashErr("request is no longer pending (timed out or decided elsewhere)")
	default:
		m.flashErr("%v", err)
	}
	m.refreshPending(false)
}

func (m *Model) alertsKey(key string) (tea.Model, tea.Cmd) {
	if len(m.pending) == 0 {
		return m, nil
	}
	r := m.pending[m.cursor[TabAlerts]]
	switch key {
	case "a", "y":
		m.resolve(r, approval.Approved)
	case "d", "n":
		m.resolve(r, approval.Denied)
	case "enter":
		rr := r
		m.modal = &rr
	}
	return m, nil
}

func (m *Model) modalKey(key string) (tea.Model, tea.Cmd) {
	r := *m.modal
	switch key {
	case "a", "y":
		m.modal = nil
		m.resolve(r, approval.Approved)
	case "d", "n":
		m.modal = nil
		m.resolve(r, approval.Denied)
	case "esc", "l":
		m.modal = nil
		m.switchTab(TabAlerts)
		m.flash("request stays pending in Alerts")
	}
	return m, nil
}

// --- import from ~/.ssh/config ---------------------------------------------------------

type importView struct {
	hosts    []sshconfig.Host
	selected map[int]bool
	cursor   int
	path     string
}

func newImportView(path string, store *config.Store) *importView {
	v := &importView{path: path, selected: map[int]bool{}}
	for _, h := range sshconfig.Parse(path) {
		if _, exists := store.ByName(h.Alias); exists {
			continue
		}
		v.hosts = append(v.hosts, h)
	}
	sort.SliceStable(v.hosts, func(i, j int) bool { return strings.ToLower(v.hosts[i].Alias) < strings.ToLower(v.hosts[j].Alias) })
	return v
}

func (m *Model) importKey(key string) (tea.Model, tea.Cmd) {
	v := m.imp
	switch key {
	case "esc", "q":
		m.imp = nil
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		if v.cursor < len(v.hosts)-1 {
			v.cursor++
		}
	case " ", "space":
		if len(v.hosts) > 0 {
			v.selected[v.cursor] = !v.selected[v.cursor]
		}
	case "enter":
		n := 0
		var errs []string
		for i, h := range v.hosts {
			if !v.selected[i] {
				continue
			}
			r := sshconfig.Resolve(h, v.path)
			host := r.HostName
			if host == "" {
				host = r.Alias
			}
			c := config.Connection{Name: r.Alias, Group: "ssh-config", Host: host, Port: r.Port, User: r.User,
				Auth: config.AuthKey, KeyPath: r.IdentityFile, AccessLevel: config.LevelNone,
				Description: "imported from " + v.path}
			if c.Port == 22 {
				c.Port = 0
			}
			if _, err := m.store.Upsert(c); err != nil {
				errs = append(errs, r.Alias+": "+err.Error())
				continue
			}
			n++
		}
		if n > 0 {
			if err := m.store.Save(); err != nil {
				m.flashErr("save failed: %v", err)
				return m, nil
			}
		}
		m.imp = nil
		if len(errs) > 0 {
			m.flashErr("imported %d, skipped: %s", n, strings.Join(errs, "; "))
		} else {
			m.flash("imported %d connection(s) with agent access none", n)
		}
	}
	return m, nil
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func copyToClipboard(text string) error {
	for _, c := range [][]string{{"pbcopy"}, {"wl-copy"}, {"xclip", "-selection", "clipboard"}} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	return fmt.Errorf("no clipboard tool (pbcopy, wl-copy or xclip)")
}
