package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
	"github.com/baeroe/tussh/internal/sshconfig"
	"github.com/baeroe/tussh/internal/sshrun"
)

// wideMin is the terminal width from which views use two panes side by side.
const wideMin = 90

// --- ordering, favorites, search ----------------------------------------------------------

// rowsAll is every connection in display order: favorites, then most recently used, then name.
func (m *Model) rowsAll() []config.Connection {
	cs := append([]config.Connection(nil), m.store.Connections...)
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Favorite != b.Favorite {
			return a.Favorite
		}
		ua, ub := m.used[a.ID], m.used[b.ID]
		if !ua.Equal(ub) {
			return ua.After(ub)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return cs
}

// rebuildRows applies order and search; the cursor stays on keepID if it is still visible.
func (m *Model) rebuildRows(keepID string) {
	q := m.query[TabConnections]
	m.rows = m.rows[:0]
	for _, c := range m.rowsAll() {
		if q == "" || matchConnection(c, q) {
			m.rows = append(m.rows, c)
		}
	}
	if keepID != "" {
		for i, c := range m.rows {
			if c.ID == keepID {
				m.cursor[TabConnections] = i
			}
		}
	}
	m.clampCursors()
	if m.detailFocus && m.detailCount() == 0 {
		m.detailFocus = false
	}
}

// matchConnection: every word of q must be found in name, host, user, description or a tag (substring,
// case-insensitive), or fuzzily (as a subsequence) in the name.
func matchConnection(c config.Connection, q string) bool {
	fields := []string{c.Name, c.Host, c.User, c.Description}
	fields = append(fields, c.Tags...)
	hay := strings.ToLower(strings.Join(fields, "\x00"))
	name := strings.ToLower(c.Name)
	for _, w := range strings.Fields(strings.ToLower(q)) {
		if !strings.Contains(hay, w) && !subsequence(name, w) {
			return false
		}
	}
	return true
}

func subsequence(s, sub string) bool {
	r := []rune(s)
	i := 0
	for _, c := range sub {
		for i < len(r) && r[i] != c {
			i++
		}
		if i == len(r) {
			return false
		}
		i++
	}
	return true
}

func (m *Model) selectedConnection() (config.Connection, bool) {
	if len(m.rows) == 0 {
		return config.Connection{}, false
	}
	return m.rows[m.cursor[TabConnections]], true
}

func (m *Model) selectedID() string {
	if c, ok := m.selectedConnection(); ok {
		return c.ID
	}
	return ""
}

func (m *Model) selectByID(id string) { m.rebuildRows(id) }

func (m *Model) allowsFor(id string) []allow.Entry {
	var out []allow.Entry
	for _, e := range m.allows {
		if e.ConnectionID == id && time.Now().Before(e.Expires) {
			out = append(out, e)
		}
	}
	return out
}

// --- keys --------------------------------------------------------------------------------

func (m *Model) connectionsKey(key string) (tea.Model, tea.Cmd) {
	if m.loadErr != nil && key != "enter" && key != "r" {
		m.flashErr("connections.json is invalid, fix it first: %v", m.loadErr)
		return m, nil
	}
	switch key {
	case "n", "a":
		m.form = newForm(nil, m.opts.Home, m.opts.SSHDir)
	case "e":
		if c, ok := m.selectedConnection(); ok {
			m.form = newForm(&c, m.opts.Home, m.opts.SSHDir)
		}
	case "x", "delete", "D":
		if c, ok := m.selectedConnection(); ok {
			m.confirm = &c
		}
	case "l":
		if c, ok := m.selectedConnection(); ok {
			c.AccessLevel = nextLevel(c.Level())
			if m.saveConnection(c) {
				m.flash("%s: agent access %s", c.Name, c.AccessLevel)
			}
		}
	case "f":
		if c, ok := m.selectedConnection(); ok {
			c.Favorite = !c.Favorite
			if m.saveConnection(c) {
				if c.Favorite {
					m.flash("★ %s pinned to the top", c.Name)
				} else {
					m.flash("%s is no longer a favorite", c.Name)
				}
			}
		}
	case "r":
		m.flash("checking reachability ...")
		return m, m.checkReach(true)
	case "t":
		if c, ok := m.selectedConnection(); ok {
			if len(c.Tunnels) == 0 {
				m.flash("%s has no tunnels (add them with e)", c.Name)
			} else {
				m.detailFocus, m.detailCursor = true, 0
			}
		}
	case "R":
		if c, ok := m.selectedConnection(); ok {
			if len(m.allowsFor(c.ID)) == 0 {
				m.flash("no remembered commands for %s", c.Name)
			} else {
				m.detailFocus, m.detailCursor = true, len(c.Tunnels)
			}
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
		config.TouchUsed(c.ID)
		m.used = config.LastUsed()
		m.rebuildRows(c.ID)
		name := c.Name
		return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
			cleanup()
			return sshDoneMsg{name: name, err: err}
		})
	}
	return m, nil
}

// saveConnection upserts and saves c, keeping it selected.
func (m *Model) saveConnection(c config.Connection) bool {
	if _, err := m.store.Upsert(c); err != nil {
		m.flashErr("%v", err)
		return false
	}
	if err := m.store.Save(); err != nil {
		m.flashErr("save failed: %v", err)
		return false
	}
	m.rebuildRows(c.ID)
	return true
}

// detailCount is the number of selectable items in the detail pane (tunnels, then remembered commands).
func (m *Model) detailCount() int {
	c, ok := m.selectedConnection()
	if !ok {
		return 0
	}
	return len(c.Tunnels) + len(m.allowsFor(c.ID))
}

func (m *Model) detailKey(key string) (tea.Model, tea.Cmd) {
	c, ok := m.selectedConnection()
	n := m.detailCount()
	if !ok || n == 0 {
		m.detailFocus = false
		return m, nil
	}
	if m.detailCursor >= n {
		m.detailCursor = n - 1
	}
	switch key {
	case "esc", "t", "R", "left", "h", "q":
		if key == "R" && m.detailCursor >= len(c.Tunnels) {
			break // R on a remembered command revokes it (below)
		}
		m.detailFocus = false
		return m, nil
	case "up", "k":
		if m.detailCursor > 0 {
			m.detailCursor--
		}
		return m, nil
	case "down", "j":
		if m.detailCursor < n-1 {
			m.detailCursor++
		}
		return m, nil
	case "?":
		m.help = true
		return m, nil
	case "enter", " ", "space", "x", "delete":
	default:
		return m, nil
	}
	if m.detailCursor < len(c.Tunnels) {
		if key == "x" || key == "delete" {
			return m, nil
		}
		return m, m.toggleTunnel(c, c.Tunnels[m.detailCursor])
	}
	e := m.allowsFor(c.ID)[m.detailCursor-len(c.Tunnels)]
	if err := allow.Revoke(e.ID); err != nil {
		m.flashErr("revoke failed: %v", err)
	} else {
		m.flash("revoked: %s", short(e.Command, 50))
	}
	m.allows = allow.List()
	if m.detailCount() == 0 {
		m.detailFocus = false
	} else if m.detailCursor >= m.detailCount() {
		m.detailCursor = m.detailCount() - 1
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
	allow.RevokeConnection(c.ID)
	config.ForgetUsed(c.ID)
	m.allows = allow.List()
	m.rebuildRows("")
	m.flash("deleted %s", c.Name)
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
	case "a":
		all := len(v.selected) < len(v.hosts)
		for i := range v.hosts {
			if all {
				v.selected[i] = true
			} else {
				delete(v.selected, i)
			}
		}
	case " ", "space":
		if len(v.hosts) > 0 {
			if v.selected[v.cursor] {
				delete(v.selected, v.cursor)
			} else {
				v.selected[v.cursor] = true
			}
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
			c := config.Connection{Name: r.Alias, Tags: []string{"ssh-config"}, Host: host, Port: r.Port, User: r.User,
				Auth: config.AuthKey, KeyPath: r.IdentityFile, AccessLevel: config.LevelNone,
				Description: "imported from " + tildify(v.path)}
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
		m.rebuildRows(m.selectedID())
		if len(errs) > 0 {
			m.flashErr("imported %d, skipped: %s", n, strings.Join(errs, "; "))
		} else {
			m.flash("imported %d connection(s) with agent access none", n)
		}
		return m, m.checkReach(false)
	}
	return m, nil
}

// --- rendering ----------------------------------------------------------------------------

func (m *Model) reachDot(id string) string {
	switch m.reach[id].state {
	case reachUp:
		return goodStyle.Render("●")
	case reachDown:
		return badStyle.Render("○")
	}
	return dimStyle.Render("◌")
}

func (m *Model) reachText(id string) string {
	ri := m.reach[id]
	switch ri.state {
	case reachUp:
		return goodStyle.Render("● reachable") + dimStyle.Render(fmt.Sprintf(" · %s · %s", latency(ri.latency), ago(ri.checked)))
	case reachDown:
		return badStyle.Render("○ unreachable") + dimStyle.Render(" · "+ri.err+" · "+ago(ri.checked))
	case reachChecking:
		return dimStyle.Render("◌ checking …")
	}
	return dimStyle.Render("◌ not checked yet (r)")
}

// listLines renders the connection rows for an inner width iw and height h.
func (m *Model) listLines(iw, h int, focused bool) []string {
	var lines []string
	cursorLine := 0
	showTarget := iw >= 64
	nameW := iw - 18
	if showTarget {
		nameW = 24
	}
	for i, c := range m.rows {
		if i > 0 && m.rows[i-1].Favorite && !c.Favorite {
			lines = append(lines, dimStyle.Render(strings.Repeat("─", iw)))
		}
		fav := " "
		if c.Favorite {
			fav = warnStyle.Render("★")
		}
		name := fit(c.Name, nameW)
		if i == m.cursor[TabConnections] {
			name = boldStyle.Render(name)
		}
		row := " " + fav + " " + m.reachDot(c.ID) + " " + name + " "
		if showTarget {
			row += dimStyle.Render(fit(c.Target(), iw-width(row)-13)) + " "
		}
		row += badge(c.Level(), false)
		if i == m.cursor[TabConnections] {
			cursorLine = len(lines)
			if focused {
				row = highlightRow(row, iw)
			} else {
				row = selStyle.Render("›") + strings.TrimPrefix(row, " ")
			}
		}
		lines = append(lines, row)
	}
	if h > 0 && len(lines) > h {
		start := 0
		if cursorLine >= h {
			start = cursorLine - h + 1
		}
		lines = lines[start:min(start+h, len(lines))]
	}
	return lines
}

func (m *Model) connectionsView(w, h int) string {
	var warn []string
	if m.loadErr != nil {
		warn = append(warn, badStyle.Render("connections.json is invalid (agents see nothing until fixed):"), badStyle.Render(m.loadErr.Error()))
	}
	if m.rules != nil && m.rules.RulesError() != nil {
		warn = append(warn, warnStyle.Render("rules.json is invalid, every agent command needs approval:"), warnStyle.Render(m.rules.RulesError().Error()))
	}
	title := "Connections"
	right := ""
	if q := m.query[TabConnections]; q != "" || m.searching {
		right = dimStyle.Render(fmt.Sprintf("%d of %d", len(m.rows), len(m.store.Connections)))
	} else if len(m.rows) > 0 {
		right = dimStyle.Render(fmt.Sprintf("%d", len(m.rows)))
	}
	listContent := func(iw, ih int) []string {
		lines := append([]string(nil), warn...)
		searchLine := ""
		if m.searching {
			searchLine = m.search.View()
		} else if q := m.query[TabConnections]; q != "" {
			searchLine = accentStyle.Render("/"+q) + dimStyle.Render("  esc clears")
		}
		avail := ih - len(lines)
		if searchLine != "" {
			avail -= 2
		}
		switch {
		case len(m.store.Connections) == 0:
			lines = append(lines, "", dimStyle.Render(" No connections yet."), "", " "+keyHints("n", "new connection"), " "+keyHints("i", "import ~/.ssh/config"))
		case len(m.rows) == 0:
			lines = append(lines, dimStyle.Render(" No match."))
		default:
			lines = append(lines, m.listLines(iw, avail, !m.detailFocus)...)
		}
		if searchLine != "" {
			for len(lines) < ih-1 {
				lines = append(lines, "")
			}
			lines = append(lines[:ih-1], searchLine)
		}
		return lines
	}
	if w >= wideMin {
		lw := min(max(w*42/100, 40), 58)
		rw := w - lw
		left := panel(title, listContent(lw-4, h-2), lw, h, !m.detailFocus, right)
		c, ok := m.selectedConnection()
		dt := "Details"
		var dl []string
		if ok {
			dt = c.Name
			dl = m.detailLines(c, rw-4)
		}
		return hjoin(left, panel(dt, dl, rw, h, m.detailFocus, ""))
	}
	// narrow: list on top, details below when there is room
	need := len(m.rows) + 2 + len(warn)
	if m.searching || m.query[TabConnections] != "" {
		need += 2
	}
	for i := 1; i < len(m.rows); i++ {
		if m.rows[i-1].Favorite && !m.rows[i].Favorite {
			need++
		}
	}
	lh := min(max(need, 5), h)
	if h-lh < 8 {
		lh = min(max(h/2, 5), h)
	}
	if h-lh < 6 || len(m.rows) == 0 {
		return panel(title, listContent(w-4, h-2), w, h, !m.detailFocus, right)
	}
	top := panel(title, listContent(w-4, lh-2), w, lh, !m.detailFocus, right)
	c, _ := m.selectedConnection()
	return top + "\n" + panel(c.Name, m.detailLines(c, w-4), w, h-lh, m.detailFocus, "")
}

func (m *Model) detailLines(c config.Connection, dw int) []string {
	const lw = 13
	var l []string
	target := c.Host
	if c.User != "" {
		target = c.User + "@" + target
	}
	target += fmt.Sprintf(":%d", c.EffectivePort())
	head := boldStyle.Render(target)
	if c.Favorite {
		head += "  " + warnStyle.Render("★ favorite")
	}
	l = append(l, head, "")
	auth := "key"
	switch {
	case c.Auth == config.AuthPassword:
		auth = "password"
		if c.HasPassword {
			auth += dimStyle.Render(" · in keychain")
		}
	case c.KeyPath != "":
		auth = "key " + tildify(c.KeyPathExpanded())
		if c.HasPassphrase {
			auth += dimStyle.Render(" · passphrase in keychain")
		}
	default:
		auth = "key " + dimStyle.Render("(ssh agent / defaults)")
	}
	l = append(l, kv("Auth", auth, lw), kv("Status", m.reachText(c.ID), lw))
	l = append(l, kv("Last used", dimStyle.Render(ago(m.used[c.ID])), lw))
	if len(c.Tags) > 0 {
		var ts []string
		for _, t := range c.Tags {
			ts = append(ts, accentStyle.Render("#"+t))
		}
		l = append(l, kv("Tags", strings.Join(ts, " "), lw))
	}
	if c.Description != "" {
		for i, d := range wrap(c.Description, dw-lw) {
			label := ""
			if i == 0 {
				label = "Description"
			}
			l = append(l, kv(label, d, lw))
		}
	}
	l = append(l, "", kv("Agent access", badge(c.Level(), true), lw))
	for _, s := range wrap(levelExplain(c.Level()), dw-lw) {
		l = append(l, strings.Repeat(" ", lw)+dimStyle.Render(s))
	}

	idx := 0
	item := func(row string) string {
		sel := m.detailFocus && idx == m.detailCursor
		idx++
		if sel {
			return highlightRow(selStyle.Render("› ")+row, dw)
		}
		return "  " + row
	}
	if len(c.Tunnels) > 0 {
		l = append(l, "", boldStyle.Render("Tunnels")+"  "+dimStyle.Render(hintIf(!m.detailFocus, "t select · enter start/stop")))
		for _, t := range c.Tunnels {
			k := tunnelKey(c, t)
			st := dimStyle.Render("○")
			switch {
			case m.tunnelBusy[k]:
				st = warnStyle.Render("◌")
			case m.tunnelState[k]:
				st = goodStyle.Render("●")
			}
			spec := fmt.Sprintf("%s:%d → %s:%d", t.BindAddr(), t.Local, t.RemoteHost, t.RemotePort)
			l = append(l, item(st+" "+fit(t.Name, 10)+" "+dimStyle.Render(spec)))
		}
	}
	if as := m.allowsFor(c.ID); len(as) > 0 {
		l = append(l, "", boldStyle.Render("Remembered commands")+"  "+dimStyle.Render(hintIf(!m.detailFocus, "R select · enter revoke")))
		for _, e := range as {
			until := "until " + clockShort(e.Expires)
			l = append(l, item(fit(oneLine(e.Command), dw-4-len(until))+" "+dimStyle.Render(until)))
		}
	}
	var recent []audit.Entry
	for _, e := range m.history {
		if e.Connection == c.Name {
			recent = append(recent, e)
			if len(recent) == 5 {
				break
			}
		}
	}
	if len(recent) > 0 {
		l = append(l, "", boldStyle.Render("Recent agent commands"))
		for _, e := range recent {
			when := ago(e.Time)
			l = append(l, "  "+decisionIcon(e)+" "+fit(oneLine(e.Command), dw-6-8)+" "+dimStyle.Render(padLeft(when, 7)))
		}
	}
	return l
}

func hintIf(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

func (m *Model) importBox() string {
	v := m.imp
	w := min(max(m.width-8, 40), 80)
	var lines []string
	for _, s := range wrap("Read-only: tussh only reads this file. Imported hosts get agent access none and the tag ssh-config.", w-4) {
		lines = append(lines, dimStyle.Render(s))
	}
	lines = append(lines, "")
	if len(v.hosts) == 0 {
		lines = append(lines, dimStyle.Render("No new concrete Host aliases found in "+tildify(v.path)+"."))
	}
	maxRows := max(m.height-10, 3)
	start := 0
	if v.cursor >= maxRows {
		start = v.cursor - maxRows + 1
	}
	for i := start; i < len(v.hosts) && i < start+maxRows; i++ {
		h := v.hosts[i]
		box := "[ ]"
		if v.selected[i] {
			box = goodStyle.Render("[x]")
		}
		detail := h.HostName
		if h.User != "" {
			detail = h.User + "@" + detail
		}
		row := box + " " + fit(h.Alias, 24) + " " + dimStyle.Render(detail)
		if i == v.cursor {
			row = highlightRow(row, w-4)
		}
		lines = append(lines, row)
	}
	lines = append(lines, "", keyHints("space", "select", "a", "all", "enter", "import", "esc", "cancel"))
	return modalBox("Import from "+tildify(v.path), lines, w, cAccent)
}

func (m *Model) confirmBox() string {
	c := *m.confirm
	lines := []string{
		"Delete " + boldStyle.Render(c.Name) + " (" + c.Target() + ")?",
		dimStyle.Render("Its stored secrets, remembered commands and tunnels go too."),
		"",
		keyHints("y", "delete", "any other key", "cancel"),
	}
	return modalBox("Delete connection", lines, min(max(m.width-8, 40), 64), cRed)
}

func latency(d time.Duration) string {
	if d < time.Millisecond {
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

// clockShort is HH:MM today, else "Mon HH:MM".
func clockShort(t time.Time) string {
	t = t.Local()
	y1, m1, d1 := t.Date()
	y2, m2, d2 := time.Now().Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04")
	}
	return t.Format("Mon 15:04")
}
