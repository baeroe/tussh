// Package tui is the tussh terminal UI (Bubble Tea): connections, tunnels, alerts (approvals), history, setup.
package tui

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/allow"
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

// reachInterval is how often hosts are probed in the background.
const reachInterval = 45 * time.Second

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
	// ExitWhenDone quits once requests were shown and none are pending any more (`tussh alerts --popup`).
	ExitWhenDone bool
	// Probe checks whether host:port accepts TCP connections (default: dial with a 3 s timeout).
	Probe func(host string, port int) error
	// TestConn runs the form's "test connection" (default sshrun.TestConnection).
	TestConn func(c config.Connection, secret string) error
	// Home is where harness configs are looked up for the Setup tab and what ~ means in the key file field
	// (default $HOME).
	Home string
	// SSHDir is where the form detects private keys (default $TUSSH_SSH_DIR, else Home/.ssh).
	SSHDir string
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

type reachMsg struct {
	id      string
	ok      bool
	latency time.Duration
	err     string
}

type testConnMsg struct {
	gen int
	err error
}

type reachState int

const (
	reachUnknown reachState = iota
	reachChecking
	reachUp
	reachDown
)

type reachInfo struct {
	state   reachState
	latency time.Duration
	checked time.Time
	err     string
}

// Model is the root Bubble Tea model.
type Model struct {
	opts       Options
	tab        Tab
	width      int
	height     int
	store      *config.Store
	storeStamp string          // config.FileStamp of the loaded connections.json
	known      map[string]bool // connection ids seen so far (to announce ones an agent created)
	loadErr    error
	rules      *classify.Classifier

	cursor [numTabs]int

	// connections
	used         map[string]time.Time
	rows         []config.Connection // sorted and filtered view of store.Connections
	reach        map[string]reachInfo
	lastReach    time.Time
	allows       []allow.Entry
	detailFocus  bool // the detail pane has focus (tunnels and remembered commands are selectable)
	detailCursor int

	// search ("/") on Connections and History
	search    textinput.Model
	searching bool
	query     [numTabs]string

	// alerts
	pending  []approval.Request
	seen     map[string]bool
	modal    *approval.Request // popup for a new request
	denyNote *textinput.Model  // inline note while denying
	denyID   string

	// history
	history      []audit.Entry
	historyMod   time.Time
	historyOpen  bool // narrow layout: show the detail of the selected entry
	histConn     string
	histDecision string

	tunnelState map[string]bool
	tunnelBusy  map[string]bool

	snippets   []harness.Snippet
	registered map[string]bool

	form       *connForm
	confirm    *config.Connection // pending delete
	imp        *importView
	help       bool
	helpScroll int

	status    string
	statusErr bool
	ticks     int
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
	if opts.Probe == nil {
		opts.Probe = tcpProbe
	}
	if opts.TestConn == nil {
		kr := opts.Keyring
		opts.TestConn = func(c config.Connection, secret string) error {
			return sshrun.TestConnection(context.Background(), c, kr, secret, 8*time.Second)
		}
	}
	if opts.Home == "" {
		opts.Home, _ = os.UserHomeDir()
	}
	if opts.SSHDir == "" {
		opts.SSHDir = os.Getenv("TUSSH_SSH_DIR")
	}
	if opts.SSHDir == "" && opts.Home != "" {
		opts.SSHDir = filepath.Join(opts.Home, ".ssh")
	}
	si := textinput.New()
	si.Prompt = "/"
	si.Placeholder = "search"
	si.CharLimit = 100
	m := &Model{opts: opts, tab: opts.Tab, seen: map[string]bool{}, tunnelState: map[string]bool{}, tunnelBusy: map[string]bool{},
		reach: map[string]reachInfo{}, search: si}
	m.snippets = harness.Snippets(opts.Bin)
	m.registered = harness.Registered(opts.Home)
	m.reload()
	m.refreshHistory()
	m.refreshPending(false)
	return m
}

func tcpProbe(host string, port int) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

// Init starts the refresh ticker and the first reachability check.
func (m *Model) Init() tea.Cmd {
	approval.Heartbeat()
	if m.opts.NoTick {
		return nil
	}
	return tea.Batch(tick(), m.checkReach(false))
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) reload() {
	m.storeStamp = config.FileStamp()
	s, err := config.Load()
	m.loadErr = err
	if err != nil {
		s = &config.Store{Version: 1}
	}
	m.store = s
	m.known = map[string]bool{}
	for _, c := range s.Connections {
		m.known[c.ID] = true
	}
	m.rules = classify.LoadRules(config.RulesFile())
	m.used = config.LastUsed()
	m.allows = allow.List()
	m.refreshTunnels()
	m.rebuildRows("")
}

// adoptStore takes over a store this process just wrote.
func (m *Model) adoptStore(s *config.Store) {
	m.store, m.loadErr, m.storeStamp = s, nil, config.FileStamp()
	for _, c := range s.Connections {
		m.known[c.ID] = true
	}
}

// refreshStore reloads connections.json when another process changed it (an agent's new_connection) and
// announces connections an agent created. An open form keeps its own copy, so unsaved edits are not touched.
func (m *Model) refreshStore() {
	stamp := config.FileStamp()
	if stamp == m.storeStamp {
		return
	}
	s, err := config.Load()
	if err != nil {
		m.storeStamp, m.loadErr = stamp, err
		return
	}
	m.store, m.loadErr, m.storeStamp = s, nil, stamp
	var fresh []config.Connection
	for _, c := range s.Connections {
		if !m.known[c.ID] {
			m.known[c.ID] = true
			if c.CreatedBy == config.CreatedByAgent && c.NeedsSetup {
				fresh = append(fresh, c)
			}
		}
	}
	m.refreshTunnels()
	m.rebuildRows(m.selectedID())
	switch {
	case len(fresh) == 1:
		m.flash("%s added %s · needs setup (e)", agentName(fresh[0]), fresh[0].Name)
	case len(fresh) > 1:
		m.flash("agents created %d connections · they need setup (e)", len(fresh))
	}
}

// agentName is who created an agent-made connection.
func agentName(c config.Connection) string {
	if c.CreatedAgent != "" {
		return oneLine(c.CreatedAgent)
	}
	return "an agent"
}

func (m *Model) refreshTunnels() {
	for _, c := range m.store.Connections {
		for _, t := range c.Tunnels {
			m.tunnelState[tunnelKey(c, t)] = sshrun.Status(c, t).Running
		}
	}
}

func (m *Model) runningTunnels() int {
	n := 0
	for _, c := range m.store.Connections {
		for _, t := range c.Tunnels {
			if m.tunnelState[tunnelKey(c, t)] {
				n++
			}
		}
	}
	return n
}

// refreshHistory reloads the audit log when it changed.
func (m *Model) refreshHistory() {
	mod := audit.LastActivity()
	if !mod.IsZero() && mod.Equal(m.historyMod) && m.history != nil {
		return
	}
	m.historyMod = mod
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
			if popup && (m.form != nil || m.denyNote != nil) {
				continue // pop up once the form is closed; never steal keys from a text input
			}
			m.seen[r.ID] = true
			if popup && m.modal == nil && m.tab != TabAlerts {
				r := r
				m.modal = &r
			}
		}
	}
	if m.modal != nil && !ids[m.modal.ID] {
		m.modal = nil // decided elsewhere or timed out
	}
	if m.denyNote != nil && !ids[m.denyID] {
		m.denyNote, m.denyID = nil, ""
		m.flashErr("the request was decided elsewhere or timed out")
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
	for _, c := range m.rowsAll() {
		for _, t := range c.Tunnels {
			rows = append(rows, tunnelRow{c, t})
		}
	}
	return rows
}

func (m *Model) rowCount(t Tab) int {
	switch t {
	case TabConnections:
		return len(m.rows)
	case TabTunnels:
		return len(m.tunnelRows())
	case TabAlerts:
		return len(m.pending)
	case TabHistory:
		return len(m.filteredHistory())
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
		return m.onTick(time.Time(msg))
	case reachMsg:
		ri := reachInfo{state: reachDown, latency: msg.latency, checked: time.Now(), err: msg.err}
		if msg.ok {
			ri.state = reachUp
		}
		m.reach[msg.id] = ri
		return m, nil
	case testConnMsg:
		if m.form != nil && m.form.testGen == msg.gen {
			m.form.testing = false
			if msg.err != nil {
				m.form.testResult, m.form.testOK = msg.err.Error(), false
			} else {
				m.form.testResult, m.form.testOK = "connected, login works", true
			}
		}
		return m, nil
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

func (m *Model) onTick(now time.Time) (tea.Model, tea.Cmd) {
	m.ticks++
	approval.Heartbeat()
	m.refreshPending(true)
	if m.opts.ExitWhenDone && len(m.seen) > 0 && len(m.pending) == 0 && m.form == nil && m.imp == nil {
		return m.quit()
	}
	m.refreshHistory()
	m.refreshStore()
	var cmds []tea.Cmd
	if m.ticks%4 == 0 { // every 2 s
		m.refreshTunnels()
		m.allows = allow.List()
		m.used = config.LastUsed()
		m.rebuildRows(m.selectedID())
	}
	if m.ticks%20 == 0 {
		m.registered = harness.Registered(m.opts.Home)
	}
	if now.Sub(m.lastReach) >= reachInterval {
		cmds = append(cmds, m.checkReach(false))
	}
	if !m.opts.NoTick {
		cmds = append(cmds, tick())
	}
	return m, tea.Batch(cmds...)
}

// checkReach probes every connection (async; never blocks the UI).
func (m *Model) checkReach(manual bool) tea.Cmd {
	m.lastReach = time.Now()
	var cmds []tea.Cmd
	probe := m.opts.Probe
	for _, c := range m.store.Connections {
		ri := m.reach[c.ID]
		if ri.state == reachChecking && !manual {
			continue
		}
		ri.state = reachChecking
		m.reach[c.ID] = ri
		id, host, port := c.ID, c.Host, c.EffectivePort()
		cmds = append(cmds, func() tea.Msg {
			start := time.Now()
			err := probe(host, port)
			msg := reachMsg{id: id, ok: err == nil, latency: time.Since(start)}
			if err != nil {
				msg.err = shortNetErr(err)
			}
			return msg
		})
	}
	return tea.Batch(cmds...)
}

func shortNetErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "unknown host"
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "timeout"):
		return "timeout"
	case strings.Contains(s, "no route"):
		return "no route to host"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func (m *Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		return m.quit()
	}
	// text inputs first: they own every key (including tab, q and digits)
	if m.denyNote != nil {
		return m.denyNoteKey(k)
	}
	if m.form != nil {
		return m.formKey(k)
	}
	if m.searching {
		return m.searchKey(k)
	}
	if m.help {
		switch key {
		case "?", "esc", "q":
			m.help = false
		case "down", "j":
			m.helpScroll++
		case "up", "k":
			m.helpScroll = max(m.helpScroll-1, 0)
		}
		return m, nil
	}
	if m.modal != nil {
		return m.modalKey(key)
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
	if m.detailFocus {
		return m.detailKey(key)
	}
	switch key {
	case "q":
		return m.quit()
	case "?":
		m.help, m.helpScroll = true, 0
		return m, nil
	case "tab":
		m.switchTab((m.tab + 1) % numTabs)
		return m, nil
	case "shift+tab":
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
	case "home", "g":
		m.cursor[m.tab] = 0
		return m, nil
	case "end", "G":
		m.cursor[m.tab] = max(0, m.rowCount(m.tab)-1)
		return m, nil
	case "/":
		if m.tab == TabConnections || m.tab == TabHistory {
			m.searching = true
			m.search.SetValue(m.query[m.tab])
			m.search.CursorEnd()
			m.search.Focus()
			return m, textinput.Blink
		}
	case "esc":
		if m.query[m.tab] != "" {
			m.setQuery("")
			return m, nil
		}
	}
	switch m.tab {
	case TabConnections:
		return m.connectionsKey(key)
	case TabTunnels:
		return m.tunnelsKey(key)
	case TabAlerts:
		return m.alertsKey(key)
	case TabHistory:
		return m.historyKey(key)
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

func (m *Model) searchKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.searching = false
		m.search.Blur()
		m.setQuery("")
		return m, nil
	case "enter":
		m.searching = false
		m.search.Blur()
		return m, nil
	case "tab", "shift+tab":
		return m, nil // never switch views while typing
	case "up", "down":
		m.searching = false
		m.search.Blur()
		return m.handleKey(k)
	}
	var cmd tea.Cmd
	m.search, cmd = m.search.Update(k)
	m.setQuery(m.search.Value())
	return m, cmd
}

func (m *Model) setQuery(q string) {
	m.query[m.tab] = q
	switch m.tab {
	case TabConnections:
		m.rebuildRows(m.selectedID())
		if q != "" {
			m.cursor[TabConnections] = 0
		}
	case TabHistory:
		m.cursor[TabHistory] = 0
	}
	m.clampCursors()
}

func (m *Model) quit() (tea.Model, tea.Cmd) {
	m.quitting = true
	approval.ClearHeartbeat()
	return m, tea.Quit
}

func (m *Model) switchTab(t Tab) {
	m.tab = t
	m.status = ""
	m.detailFocus = false
	switch t {
	case TabHistory:
		m.refreshHistory()
	case TabTunnels:
		m.refreshTunnels()
	case TabAlerts:
		m.refreshPending(false)
	case TabSetup:
		m.registered = harness.Registered(m.opts.Home)
	}
}

func (m *Model) tunnelsKey(key string) (tea.Model, tea.Cmd) {
	rows := m.tunnelRows()
	if (key != "enter" && key != " " && key != "space") || len(rows) == 0 {
		return m, nil
	}
	r := rows[m.cursor[TabTunnels]]
	return m, m.toggleTunnel(r.conn, r.tunnel)
}

func (m *Model) toggleTunnel(c config.Connection, t config.Tunnel) tea.Cmd {
	k := tunnelKey(c, t)
	if m.tunnelBusy[k] {
		return nil
	}
	m.tunnelBusy[k] = true
	running := m.tunnelState[k]
	if running {
		m.flash("stopping %s ...", t.Name)
	} else {
		m.flash("starting %s ...", t.Name)
	}
	return func() tea.Msg {
		if running {
			sshrun.StopTunnel(c, t)
			return tunnelDoneMsg{key: k}
		}
		_, err := sshrun.StartTunnel(c, t, 15*time.Second)
		return tunnelDoneMsg{key: k, err: err, up: err == nil}
	}
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
