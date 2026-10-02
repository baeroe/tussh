package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

// View renders the UI: header, the current tab's body, overlays and the footer.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	w, h := m.width, m.height
	if w <= 0 || h <= 0 {
		w, h = 100, 30
	}
	bh := max(h-2, 3)
	body := m.body(w, bh)
	switch {
	case m.help:
		body = overlay(body, m.helpBox(w, bh), w, bh)
	case m.modal != nil:
		body = overlay(body, m.alertCard(*m.modal, min(w-2, 84), 0, 0, 1, true), w, bh)
	case m.form != nil:
		body = overlay(body, m.formBox(w, bh), w, bh)
	case m.imp != nil:
		body = overlay(body, m.importBox(), w, bh)
	case m.confirm != nil:
		body = overlay(body, m.confirmBox(), w, bh)
	}
	return m.header(w) + "\n" + clampLines(body, w, bh) + "\n" + m.footer(w)
}

// clampLines makes s exactly h lines of at most w cells.
func clampLines(s string, w, h int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	for i, l := range lines {
		if width(l) > w {
			lines[i] = fit(l, w)
		}
	}
	return strings.Join(lines, "\n")
}

func (m *Model) body(w, h int) string {
	switch m.tab {
	case TabConnections:
		return m.connectionsView(w, h)
	case TabTunnels:
		return m.tunnelsView(w, h)
	case TabAlerts:
		return m.alertsView(w, h)
	case TabHistory:
		return m.historyView(w, h)
	case TabSetup:
		return m.setupView(w, h)
	}
	return ""
}

// --- header and footer -----------------------------------------------------------------------

func (m *Model) header(w int) string {
	chips := func(compact bool) string {
		var parts []string
		if n := len(m.pending); n > 0 {
			t := fmt.Sprintf("%d pending", n)
			if compact {
				t = fmt.Sprintf("! %d", n)
			}
			parts = append(parts, alertChip.Render(t))
		}
		if n := m.runningTunnels(); n > 0 {
			t := fmt.Sprintf("%d tunnel", n)
			if n > 1 {
				t += "s"
			}
			if compact {
				t = fmt.Sprintf("⇄ %d", n)
			}
			parts = append(parts, goodStyle.Render(t))
		}
		if last := audit.LastActivity(); !last.IsZero() {
			t := "agent " + ago(last)
			if compact {
				t = ago(last)
			}
			parts = append(parts, dimStyle.Render(t))
		}
		return strings.Join(parts, dimStyle.Render(" · "))
	}
	tabs := func(short bool) string {
		var parts []string
		for i, n := range tabNames {
			label := fmt.Sprintf("%d %s", i+1, n)
			if short {
				label = fmt.Sprintf("%d %s", i+1, n[:min(len(n), 4)])
				if Tab(i) == TabConnections {
					label = fmt.Sprintf("%d Conn", i+1)
				}
			}
			if Tab(i) == m.tab {
				parts = append(parts, tabActive.Render(label))
			} else if Tab(i) == TabAlerts && len(m.pending) > 0 {
				parts = append(parts, tabInactive.Foreground(cRed).Bold(true).Render(label))
			} else {
				parts = append(parts, tabInactive.Faint(true).Render(label))
			}
		}
		return strings.Join(parts, "")
	}
	left := " " + appName.Render("tussh") + "  "
	for _, v := range []struct {
		short, compact bool
	}{{false, false}, {false, true}, {true, true}} {
		l := left + tabs(v.short)
		c := chips(v.compact)
		if width(l)+width(c)+2 <= w {
			return l + strings.Repeat(" ", w-width(l)-width(c)-1) + c + " "
		}
	}
	return fit(left+tabs(true), w)
}

func (m *Model) hints() string {
	switch {
	case m.help:
		return keyHints("?", "close help")
	case m.denyNote != nil:
		return keyHints("enter", "deny with note", "esc", "cancel")
	case m.modal != nil:
		return keyHints("y", "approve", "m", "remember", "n", "deny", "esc", "later")
	case m.form != nil:
		return keyHints("tab", "next field", "ctrl+s", "save", "ctrl+t", "test", "esc", "cancel")
	case m.imp != nil:
		return keyHints("space", "select", "enter", "import", "esc", "cancel")
	case m.confirm != nil:
		return keyHints("y", "delete", "any key", "cancel")
	case m.searching:
		return keyHints("enter", "keep filter", "esc", "clear")
	case m.detailFocus:
		return keyHints("↑↓", "select", "enter", "start/stop · revoke", "esc", "back")
	}
	switch m.tab {
	case TabConnections:
		return keyHints("enter", "connect", "n", "new", "/", "search", "?", "help")
	case TabTunnels:
		return keyHints("enter", "start/stop", "?", "help", "q", "quit")
	case TabAlerts:
		if len(m.pending) > 0 {
			return keyHints("y", "approve", "m", "remember", "n", "deny", "?", "help")
		}
		return keyHints("tab", "next view", "?", "help", "q", "quit")
	case TabHistory:
		return keyHints("c", "connection", "d", "decision", "/", "search", "?", "help")
	case TabSetup:
		return keyHints("enter", "copy snippet", "?", "help", "q", "quit")
	}
	return keyHints("?", "help")
}

func (m *Model) footer(w int) string {
	left := " " + m.hints()
	if m.status == "" {
		return fit(left, w)
	}
	st := goodStyle
	if m.statusErr {
		st = badStyle
	}
	status := m.status
	room := w - width(left) - 3
	if room < 20 {
		return fit(" "+st.Render(status), w)
	}
	status = fit(status, min(room, width(status)))
	return left + strings.Repeat(" ", w-width(left)-width(status)-1) + st.Render(status) + " "
}

// --- help ---------------------------------------------------------------------------------

func (m *Model) helpBox(w, h int) string {
	sections := []struct {
		title string
		keys  []string
	}{
		{"Everywhere", []string{"tab ⇧tab", "next / previous view", "1-5", "jump to a view", "↑↓ j k", "move", "?", "this help", "q", "quit"}},
		{"Connections", []string{"enter", "connect (interactive ssh)", "n / e / x", "new / edit / delete", "f", "favorite (pin to the top)", "l", "cycle agent access level", "/", "search (name, host, tags …)", "r", "check reachability now", "t", "tunnels (enter starts/stops)", "R", "remembered commands (revoke)", "i", "import from ~/.ssh/config"}},
		{"Alerts", []string{"y", "approve", "m", "approve & remember this command", "n", "deny, with an optional note"}},
		{"History", []string{"c", "filter by connection", "d", "filter by decision", "/", "search commands", "esc", "clear filters"}},
		{"Form", []string{"tab / ↑↓", "next / previous field", "←→", "change a choice", "ctrl+t", "test the connection", "ctrl+s", "save", "esc", "cancel"}},
	}
	var cols [][]string
	for _, s := range sections {
		var l []string
		l = append(l, boldStyle.Render(s.title))
		for i := 0; i+1 < len(s.keys); i += 2 {
			l = append(l, keyStyle.Render(fit(s.keys[i], 14))+dimStyle.Render(s.keys[i+1]))
		}
		l = append(l, "")
		cols = append(cols, l)
	}
	var lines []string
	bw := min(w-2, 100)
	if bw >= 96 {
		// two columns
		left := append(append([]string{}, cols[0]...), cols[2]...)
		left = append(left, cols[3]...)
		right := append(append([]string{}, cols[1]...), cols[4]...)
		cw := (bw - 4) / 2
		for i := 0; i < max(len(left), len(right)); i++ {
			a, b := "", ""
			if i < len(left) {
				a = left[i]
			}
			if i < len(right) {
				b = right[i]
			}
			lines = append(lines, fit(a, cw)+b)
		}
	} else {
		bw = min(w-2, 60)
		for _, c := range cols {
			lines = append(lines, c...)
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	title := "Keys"
	if room := h - 2; len(lines) > room && room > 2 {
		m.helpScroll = min(max(m.helpScroll, 0), len(lines)-room)
		lines = lines[m.helpScroll : m.helpScroll+room]
		title = "Keys (↑↓ scroll)"
	}
	return modalBox(title, lines, bw, cAccent)
}

// --- tunnels -------------------------------------------------------------------------------

func (m *Model) tunnelsView(w, h int) string {
	rows := m.tunnelRows()
	if len(rows) == 0 {
		return panel("Tunnels", []string{"", dimStyle.Render(" No tunnels. Add them to a connection (e, field Tunnels): name=local:host:port."),
			dimStyle.Render(" Tunnels run as background ssh -N -L processes and keep running after tussh exits."),
			dimStyle.Render(" Agents cannot start tunnels.")}, w, h, true, "")
	}
	iw := w - 4
	lines := []string{dimStyle.Render(fit("", 2) + fit("connection", 17) + fit("tunnel", 11) + "forward")}
	start := 0
	if c := m.cursor[TabTunnels]; c >= h-3 {
		start = c - (h - 3) + 1
	}
	for i := start; i < len(rows) && i < start+h-3; i++ {
		r := rows[i]
		k := tunnelKey(r.conn, r.tunnel)
		state := dimStyle.Render("○ stopped")
		if m.tunnelBusy[k] {
			state = warnStyle.Render("◌ …")
		} else if m.tunnelState[k] {
			state = goodStyle.Render("● running")
		}
		spec := fmt.Sprintf("%s:%d → %s:%d", r.tunnel.BindAddr(), r.tunnel.Local, r.tunnel.RemoteHost, r.tunnel.RemotePort)
		row := "  " + fit(r.conn.Name, 16) + " " + fit(r.tunnel.Name, 10) + " " + fit(spec, max(iw-2-16-1-10-1-1-9, 10)) + " " + state
		if i == m.cursor[TabTunnels] {
			row = highlightRow(row, iw)
		}
		lines = append(lines, row)
	}
	return panel("Tunnels", lines, w, h, true, dimStyle.Render(fmt.Sprintf("%d running", m.runningTunnels())))
}

// --- setup ---------------------------------------------------------------------------------

func (m *Model) setupView(w, h int) string {
	pw := w - 4
	lw := 9
	path := func(label, p string) string {
		return kv(label, ellipsizeMiddle(tildify(p), pw-lw), lw)
	}
	info := []string{
		path("binary", m.opts.Bin),
		path("config", config.ConfigDir()),
		path("state", config.StateDir()),
	}
	for i, s := range wrap(tildifyAll(secrets.Describe()), pw-lw) {
		label := ""
		if i == 0 {
			label = "secrets"
		}
		info = append(info, kv(label, s, lw))
	}
	top := panel("Paths", info, w, len(info)+2, false, "")
	rest := h - len(info) - 2
	sel := m.snippets[m.cursor[TabSetup]]
	detail := func(dw int) []string {
		var l []string
		status := dimStyle.Render("not registered (user config)")
		if m.registered[sel.Harness] {
			status = goodStyle.Render("✓ registered")
		}
		l = append(l, boldStyle.Render(sel.Name)+"  "+status, dimStyle.Render(sel.How), "")
		for _, s := range strings.Split(sel.Text, "\n") {
			for _, x := range hardWrap(s, dw-2) {
				l = append(l, accentStyle.Render("│ ")+codeStyle.Render(x))
			}
		}
		if sel.Note != "" {
			l = append(l, "")
			for _, s := range wrap(sel.Note, dw) {
				l = append(l, warnStyle.Render(s))
			}
		}
		l = append(l, "", dimStyle.Render("enter copies the snippet to the clipboard"))
		return l
	}
	if w >= wideMin {
		lw := 28
		left := panel("Harnesses", m.setupList(lw-4), lw, rest, true, "")
		return top + "\n" + hjoin(left, panel("Register", detail(w-lw-4), w-lw, rest, false, ""))
	}
	// narrow: harness list, snippet, and the paths when there is room
	lh := len(m.snippets) + 2
	full := h - lh
	if full-len(info)-2 >= 7 {
		return panel("Harnesses", m.setupList(w-4), w, lh, true, "") + "\n" + panel("Register", detail(w-4), w, full-len(info)-2, false, "") + "\n" + top
	}
	return panel("Harnesses", m.setupList(w-4), w, lh, true, "") + "\n" + panel("Register", detail(w-4), w, full, false, "")
}

func (m *Model) setupList(iw int) []string {
	var list []string
	for i, s := range m.snippets {
		mark := dimStyle.Render("·")
		if m.registered[s.Harness] {
			mark = goodStyle.Render("✓")
		}
		row := " " + mark + " " + s.Name
		if i == m.cursor[TabSetup] {
			row = highlightRow(row, iw)
		}
		list = append(list, row)
	}
	return list
}

// tildifyAll replaces $HOME/ in free text with ~/.
func tildifyAll(s string) string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" || h == "/" {
		return s
	}
	return strings.ReplaceAll(s, h+"/", "~/")
}
