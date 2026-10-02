package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

var (
	accent      = lipgloss.AdaptiveColor{Light: "#5A4FCF", Dark: "#9D8CFF"}
	dim         = lipgloss.AdaptiveColor{Light: "#777777", Dark: "#8A8A8A"}
	warn        = lipgloss.AdaptiveColor{Light: "#B54708", Dark: "#FDB022"}
	bad         = lipgloss.AdaptiveColor{Light: "#C0262D", Dark: "#FF6B6B"}
	good        = lipgloss.AdaptiveColor{Light: "#18794E", Dark: "#4CC38A"}
	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(accent).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(dim).Padding(0, 1)
	selStyle    = lipgloss.NewStyle().Bold(true).Foreground(accent)
	dimStyle    = lipgloss.NewStyle().Foreground(dim)
	warnStyle   = lipgloss.NewStyle().Foreground(warn).Bold(true)
	badStyle    = lipgloss.NewStyle().Foreground(bad)
	goodStyle   = lipgloss.NewStyle().Foreground(good)
	titleStyle  = lipgloss.NewStyle().Bold(true)
	modalStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(warn).Padding(1, 2)
)

func levelStyle(l string) lipgloss.Style {
	switch l {
	case config.LevelTrusted:
		return lipgloss.NewStyle().Foreground(warn)
	case config.LevelApproveEach:
		return lipgloss.NewStyle().Foreground(accent)
	case config.LevelReadOnly:
		return goodStyle
	}
	return dimStyle
}

// View renders the UI.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.tabBar())
	b.WriteString("\n\n")
	switch {
	case m.modal != nil:
		b.WriteString(m.modalView())
	case m.form != nil:
		b.WriteString(m.formView())
	case m.imp != nil:
		b.WriteString(m.importViewString())
	default:
		b.WriteString(m.body())
	}
	b.WriteString("\n")
	if m.status != "" {
		st := goodStyle
		if m.statusErr {
			st = badStyle
		}
		b.WriteString(st.Render(m.status) + "\n")
	}
	b.WriteString(dimStyle.Render(m.help()))
	return m.fit(b.String())
}

// fit truncates lines to the terminal width.
func (m *Model) fit(s string) string {
	if m.width <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if lipgloss.Width(l) > m.width {
			lines[i] = truncateANSI(l, m.width)
		}
	}
	return strings.Join(lines, "\n")
}

func truncateANSI(s string, w int) string {
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func (m *Model) tabBar() string {
	var parts []string
	for i, n := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, n)
		if Tab(i) == TabAlerts && len(m.pending) > 0 {
			label += fmt.Sprintf(" (%d)", len(m.pending))
		}
		if Tab(i) == m.tab {
			parts = append(parts, tabActive.Render(label))
		} else if Tab(i) == TabAlerts && len(m.pending) > 0 {
			parts = append(parts, warnStyle.Padding(0, 1).Render(label))
		} else {
			parts = append(parts, tabInactive.Render(label))
		}
	}
	return titleStyle.Render("tussh") + "  " + strings.Join(parts, "")
}

func (m *Model) help() string {
	switch {
	case m.modal != nil:
		return "a approve · d deny · esc later (stays in Alerts)"
	case m.form != nil:
		return "tab/↑↓ move · ←→ change choice · ctrl+s save · esc cancel"
	case m.imp != nil:
		return "space select · enter import · esc cancel"
	case m.confirm != nil:
		return "y delete · any other key cancels"
	}
	common := " · tab/1-5 switch · q quit"
	switch m.tab {
	case TabConnections:
		return "enter connect · n new · e edit · x delete · l agent access · i import ~/.ssh/config" + common
	case TabTunnels:
		return "enter start/stop" + common
	case TabAlerts:
		return "a approve · d deny · enter details" + common
	case TabHistory:
		return "enter details" + common
	case TabSetup:
		return "enter copy" + common
	}
	return common
}

// window returns the visible slice bounds for a list of n rows around cursor.
func (m *Model) window(n, cursor, reserved int) (int, int) {
	h := m.height - reserved
	if h < 5 || m.height == 0 {
		h = 1000
	}
	start := 0
	if cursor >= h {
		start = cursor - h + 1
	}
	end := start + h
	if end > n {
		end = n
	}
	return start, end
}

func (m *Model) body() string {
	switch m.tab {
	case TabConnections:
		return m.connectionsView()
	case TabTunnels:
		return m.tunnelsView()
	case TabAlerts:
		return m.alertsView()
	case TabHistory:
		return m.historyView()
	case TabSetup:
		return m.setupView()
	}
	return ""
}

func cursorMark(sel bool) string {
	if sel {
		return selStyle.Render("› ")
	}
	return "  "
}

func (m *Model) connectionsView() string {
	var b strings.Builder
	if m.loadErr != nil {
		b.WriteString(badStyle.Render("connections.json is invalid (agents see nothing until fixed): "+m.loadErr.Error()) + "\n\n")
	}
	if m.rules != nil && m.rules.RulesError() != nil {
		b.WriteString(warnStyle.Render("rules.json is invalid, every agent command needs approval: "+m.rules.RulesError().Error()) + "\n\n")
	}
	if m.confirm != nil {
		b.WriteString(warnStyle.Render(fmt.Sprintf("Delete %s (%s) and its stored secrets? y/N", m.confirm.Name, m.confirm.Target())) + "\n\n")
	}
	cs := m.store.Connections
	if len(cs) == 0 {
		b.WriteString(dimStyle.Render("No connections yet. Press n to add one or i to import from ~/.ssh/config.") + "\n")
		return b.String()
	}
	start, end := m.window(len(cs), m.cursor[TabConnections], 8)
	group := "\x00"
	for i := start; i < end; i++ {
		c := cs[i]
		if c.Group != group {
			group = c.Group
			g := group
			if g == "" {
				g = "(no group)"
			}
			b.WriteString(dimStyle.Render(g) + "\n")
		}
		sel := i == m.cursor[TabConnections]
		name := c.Name
		if sel {
			name = selStyle.Render(name)
		}
		auth := "key"
		if c.Auth == config.AuthPassword {
			auth = "password"
		}
		line := fmt.Sprintf("%s%-24s %-34s %-9s %s", cursorMark(sel), name, c.Target(), auth, levelStyle(c.Level()).Render(c.Level()))
		if c.Description != "" {
			line += dimStyle.Render("  " + c.Description)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *Model) tunnelsView() string {
	rows := m.tunnelRows()
	if len(rows) == 0 {
		return dimStyle.Render("No tunnels. Add them to a connection (e, field Tunnels): name=local:host:port.") + "\n" +
			dimStyle.Render("Tunnels run as background ssh -N -L processes and keep running after tussh exits. Agents cannot start tunnels.") + "\n"
	}
	var b strings.Builder
	for i, r := range rows {
		sel := i == m.cursor[TabTunnels]
		k := tunnelKey(r.conn, r.tunnel)
		state := dimStyle.Render("stopped")
		if m.tunnelBusy[k] {
			state = warnStyle.Render("…")
		} else if m.tunnelState[k] {
			state = goodStyle.Render("running")
		}
		b.WriteString(fmt.Sprintf("%s%-20s %-12s %s:%d → %s:%d  %s\n", cursorMark(sel), r.conn.Name, r.tunnel.Name,
			r.tunnel.BindAddr(), r.tunnel.Local, r.tunnel.RemoteHost, r.tunnel.RemotePort, state))
	}
	return b.String()
}

func remaining(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Until(t).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%s left", d)
}

func (m *Model) alertsView() string {
	if len(m.pending) == 0 {
		return dimStyle.Render("No pending approval requests.") + "\n"
	}
	var b strings.Builder
	for i, r := range m.pending {
		sel := i == m.cursor[TabAlerts]
		cmd := short(r.Command, 70)
		if sel {
			cmd = selStyle.Render(cmd)
		}
		b.WriteString(fmt.Sprintf("%s%-18s %s  %s\n", cursorMark(sel), r.Connection, cmd, dimStyle.Render(remaining(r.Expires))))
		if sel {
			b.WriteString(m.requestDetails(r, "    "))
		}
	}
	return b.String()
}

func (m *Model) requestDetails(r approval.Request, indent string) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(indent + dimStyle.Render(fmt.Sprintf("%-14s", k)) + v + "\n")
		}
	}
	line("connection", fmt.Sprintf("%s (%s, %s)", r.Connection, r.Target, r.AccessLevel))
	line("agent", r.Agent)
	line("justification", r.Justification)
	for i, reason := range r.Reasons {
		k := ""
		if i == 0 {
			k = "needs approval"
		}
		b.WriteString(indent + dimStyle.Render(fmt.Sprintf("%-14s", k)) + warnStyle.Render(reason) + "\n")
	}
	line("requested", r.Created.Format("15:04:05")+"  ("+remaining(r.Expires)+", then auto-deny)")
	return b.String()
}

func (m *Model) modalView() string {
	r := *m.modal
	var b strings.Builder
	b.WriteString(warnStyle.Render("Agent approval request") + "\n\n")
	b.WriteString(titleStyle.Render("$ ") + r.Command + "\n\n")
	b.WriteString(m.requestDetails(r, ""))
	b.WriteString("\n" + goodStyle.Render("[a] approve") + "   " + badStyle.Render("[d] deny") + "   " + dimStyle.Render("[esc] later"))
	w := m.width - 4
	if w <= 20 || w > 100 {
		w = 100
	}
	return modalStyle.Width(w).Render(b.String()) + "\n"
}

func (m *Model) historyView() string {
	if len(m.history) == 0 {
		return dimStyle.Render("No agent requests yet.") + "\n"
	}
	var b strings.Builder
	start, end := m.window(len(m.history), m.cursor[TabHistory], 8)
	for i := start; i < end; i++ {
		e := m.history[i]
		sel := i == m.cursor[TabHistory]
		dec := e.Decision
		switch dec {
		case "auto", "approved":
			dec = goodStyle.Render(fmt.Sprintf("%-8s", dec))
		case "denied", "timeout", "blocked":
			dec = badStyle.Render(fmt.Sprintf("%-8s", dec))
		}
		exit := ""
		if e.ExitCode != nil {
			exit = fmt.Sprintf("exit %d", *e.ExitCode)
		} else if e.TimedOut {
			exit = "timed out"
		}
		cmd := short(e.Command, 60)
		if sel {
			cmd = selStyle.Render(cmd)
		}
		b.WriteString(fmt.Sprintf("%s%s %-16s %s %s %s\n", cursorMark(sel), dimStyle.Render(e.Time.Local().Format("01-02 15:04:05")),
			short(e.Connection, 16), dec, cmd, dimStyle.Render(exit)))
		if sel && m.historyOpen {
			ind := "    "
			kv := func(k, v string) {
				if v != "" {
					b.WriteString(ind + dimStyle.Render(fmt.Sprintf("%-14s", k)) + v + "\n")
				}
			}
			kv("command", e.Command)
			kv("level", e.AccessLevel)
			kv("agent", e.Agent)
			kv("justification", e.Justification)
			kv("decided by", e.DecidedBy)
			kv("reasons", strings.Join(e.Reasons, "; "))
			kv("error", e.Error)
			if e.DurationMS > 0 {
				kv("duration", fmt.Sprintf("%d ms", e.DurationMS))
			}
		}
	}
	return b.String()
}

func (m *Model) setupView() string {
	var b strings.Builder
	b.WriteString(dimStyle.Render("Register the MCP server (stdio) with your agent harness. Enter copies the snippet.") + "\n")
	b.WriteString(dimStyle.Render("binary: "+m.opts.Bin+" · secrets: "+secrets.Describe()) + "\n")
	b.WriteString(dimStyle.Render("config: "+config.ConfigDir()+" · state: "+config.StateDir()) + "\n\n")
	for i, s := range m.snippets {
		sel := i == m.cursor[TabSetup]
		name := s.Name
		if sel {
			name = selStyle.Render(name)
		}
		b.WriteString(cursorMark(sel) + name + dimStyle.Render("  ("+s.How+")") + "\n")
		if sel {
			for _, l := range strings.Split(s.Text, "\n") {
				b.WriteString("    " + l + "\n")
			}
			if s.Note != "" {
				b.WriteString("    " + warnStyle.Render(s.Note) + "\n")
			}
		}
	}
	return b.String()
}

func (m *Model) formView() string {
	f := m.form
	var b strings.Builder
	title := "New connection"
	if f.orig != nil {
		title = "Edit " + f.orig.Name
	}
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for i := 0; i < numFields; i++ {
		if !f.visible(i) {
			continue
		}
		label := fmt.Sprintf("%-16s", fieldLabels[i])
		if i == f.focus {
			label = selStyle.Render(label)
		} else {
			label = dimStyle.Render(label)
		}
		var v string
		switch i {
		case fAuth:
			v = choice([]string{config.AuthKey, config.AuthPassword}, f.auth, i == f.focus)
		case fLevel:
			v = choice(config.Levels, f.level, i == f.focus)
		default:
			v = f.inputs[i].View()
		}
		b.WriteString(cursorMark(i == f.focus) + label + v + "\n")
	}
	b.WriteString("\n" + dimStyle.Render(levelHelp(f.level)) + "\n")
	if f.err != "" {
		b.WriteString(badStyle.Render(f.err) + "\n")
	}
	return b.String()
}

func levelHelp(l string) string {
	switch l {
	case config.LevelReadOnly:
		return "read-only: allowlisted read-only commands run automatically, anything else needs your approval."
	case config.LevelApproveEach:
		return "approve-each: every agent command needs your approval."
	case config.LevelTrusted:
		return "trusted: agent commands run automatically, except sensitive ones (secrets, deletion, destructive ops)."
	}
	return "none: agents cannot see or use this connection."
}

func choice(opts []string, cur string, focused bool) string {
	var parts []string
	for _, o := range opts {
		if o == cur {
			if focused {
				parts = append(parts, selStyle.Render("‹"+o+"›"))
			} else {
				parts = append(parts, titleStyle.Render(o))
			}
		} else {
			parts = append(parts, dimStyle.Render(o))
		}
	}
	return strings.Join(parts, "  ")
}

func (m *Model) importViewString() string {
	v := m.imp
	var b strings.Builder
	b.WriteString(titleStyle.Render("Import from "+v.path) + dimStyle.Render("  (read-only; imported with agent access none)") + "\n\n")
	if len(v.hosts) == 0 {
		b.WriteString(dimStyle.Render("No new concrete Host aliases found.") + "\n")
		return b.String()
	}
	for i, h := range v.hosts {
		box := "[ ]"
		if v.selected[i] {
			box = goodStyle.Render("[x]")
		}
		name := h.Alias
		if i == v.cursor {
			name = selStyle.Render(name)
		}
		detail := h.HostName
		if h.User != "" {
			detail = h.User + "@" + detail
		}
		b.WriteString(fmt.Sprintf("%s%s %s  %s\n", cursorMark(i == v.cursor), box, name, dimStyle.Render(detail)))
	}
	return b.String()
}
