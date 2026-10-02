package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/config"
)

func (m *Model) resolve(r approval.Request, decision, note string) bool {
	err := m.opts.Queue.Resolve(r.ID, decision, "tui", note)
	ok := false
	switch {
	case err == nil:
		ok = true
		m.flash("%s: %s on %s", decision, short(r.Command, 50), r.Connection)
	case err == approval.ErrAlreadyDecided || err == approval.ErrUnknown:
		m.flashErr("request is no longer pending (timed out or decided elsewhere)")
	default:
		m.flashErr("%v", err)
	}
	m.refreshPending(false)
	return ok
}

// remember approves r and allows exactly this command on this connection for the configured TTL.
func (m *Model) remember(r approval.Request) {
	if r.ConnectionID == "" {
		m.flashErr("cannot remember: the request has no connection id")
		return
	}
	ttl := config.LoadSettings().RememberTTL()
	e, err := allow.Add(r.ConnectionID, r.Connection, r.Command, ttl, "tui")
	if err != nil {
		m.flashErr("remember failed: %v", err)
		return
	}
	if !m.resolve(r, approval.Approved, "") {
		_ = allow.Revoke(e.ID) // nothing was approved, so nothing is remembered
		return
	}
	m.allows = allow.List()
	m.flash("approved, and remembered on %s until %s", r.Connection, clockShort(e.Expires))
}

func (m *Model) startDeny(r approval.Request) tea.Cmd {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = "optional note for the agent"
	ti.CharLimit = 300
	ti.Focus()
	m.denyNote, m.denyID = &ti, r.ID
	return textinput.Blink
}

func (m *Model) denyNoteKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.denyNote, m.denyID = nil, ""
		m.flash("deny cancelled")
		return m, nil
	case "tab", "shift+tab":
		return m, nil
	case "enter":
		note := strings.TrimSpace(m.denyNote.Value())
		id := m.denyID
		m.denyNote, m.denyID = nil, ""
		for _, r := range m.pending {
			if r.ID == id {
				if m.modal != nil && m.modal.ID == id {
					m.modal = nil
				}
				m.resolve(r, approval.Denied, note)
				return m, nil
			}
		}
		m.flashErr("request is no longer pending (timed out or decided elsewhere)")
		return m, nil
	}
	var cmd tea.Cmd
	ti, cmd := m.denyNote.Update(k)
	m.denyNote = &ti
	return m, cmd
}

func (m *Model) alertsKey(key string) (tea.Model, tea.Cmd) {
	if len(m.pending) == 0 {
		return m, nil
	}
	r := m.pending[m.cursor[TabAlerts]]
	switch key {
	case "y", "a":
		m.resolve(r, approval.Approved, "")
	case "m":
		m.remember(r)
	case "n", "d":
		return m, m.startDeny(r)
	}
	return m, nil
}

func (m *Model) modalKey(key string) (tea.Model, tea.Cmd) {
	r := *m.modal
	switch key {
	case "y", "a":
		m.modal = nil
		m.resolve(r, approval.Approved, "")
	case "m":
		m.modal = nil
		m.remember(r)
	case "n", "d":
		return m, m.startDeny(r)
	case "esc", "l":
		m.modal = nil
		m.switchTab(TabAlerts)
		for i, p := range m.pending {
			if p.ID == r.ID {
				m.cursor[TabAlerts] = i
			}
		}
		m.flash("request stays pending in Alerts")
	case "?":
		m.help = true
	}
	return m, nil
}

// --- rendering ----------------------------------------------------------------------------

// highlightCommand colors shell operators and the command word; it works on plain text lines.
func highlightCommand(line string, first bool) string {
	var b strings.Builder
	word := first
	for i, part := range strings.SplitAfter(line, " ") {
		trimmed := strings.TrimSpace(part)
		switch {
		case trimmed == "":
			b.WriteString(part)
			continue
		case strings.ContainsAny(trimmed, "|;&<>") && strings.Trim(trimmed, "|;&<>0123456789") == "":
			b.WriteString(warnStyle.Bold(true).Render(trimmed) + part[len(strings.TrimRight(part, " ")):])
			word = true
			continue
		case word && i >= 0:
			b.WriteString(codeStyle.Render(trimmed) + part[len(strings.TrimRight(part, " ")):])
			word = false
			continue
		case strings.HasPrefix(trimmed, "-"):
			b.WriteString(accentStyle.Render(trimmed) + part[len(strings.TrimRight(part, " ")):])
			continue
		}
		b.WriteString(part)
	}
	return b.String()
}

// countdown renders a bar with the seconds left until the request is denied automatically.
func countdown(r approval.Request, w int) string {
	total := r.Expires.Sub(r.Created)
	left := time.Until(r.Expires)
	if left < 0 {
		left = 0
	}
	frac := 0.0
	if total > 0 {
		frac = float64(left) / float64(total)
	}
	label := fmt.Sprintf(" %ds left, then auto-deny", int(left.Round(time.Second).Seconds()))
	bw := max(w-width(label), 6)
	full := int(frac*float64(bw) + 0.5)
	st := goodStyle
	switch {
	case frac < 0.2:
		st = badStyle
	case frac < 0.5:
		st = warnStyle
	}
	return st.Render(strings.Repeat("█", full)) + dimStyle.Render(strings.Repeat("░", bw-full)) + dimStyle.Render(label)
}

// alertCard renders one approval request as a bordered card of width w. It is used by the Alerts tab,
// the popup for new requests and `tussh alerts --popup`.
func (m *Model) alertCard(r approval.Request, w, h, idx, total int, focused bool) string {
	iw := w - 4
	var l []string
	head := boldStyle.Render(oneLine(r.Connection)) + "  " + badge(r.AccessLevel, true)
	if r.Agent != "" {
		head += dimStyle.Render("  via ") + oneLine(r.Agent)
	}
	l = append(l, head)
	if r.Target != "" {
		l = append(l, dimStyle.Render(r.Target))
	}
	l = append(l, "")
	// command block
	cmdLines := hardWrap(r.Command, iw-4)
	if len(cmdLines) > 8 {
		cmdLines = append(cmdLines[:7], "…")
	}
	bar := lipgloss.NewStyle().Foreground(cYellow).Render("┃")
	for i, cl := range cmdLines {
		prefix := "  "
		if i == 0 {
			prefix = warnStyle.Bold(true).Render("$ ")
		}
		l = append(l, bar+" "+prefix+highlightCommand(cl, i == 0))
	}
	l = append(l, "")
	const lw = 12
	for i, reason := range r.Reasons {
		label := ""
		if i == 0 {
			label = "Why"
		}
		for j, s := range wrap(reason, iw-lw) {
			if j > 0 {
				label = ""
			}
			l = append(l, kv(label, warnStyle.Render(s), lw))
		}
	}
	if r.Justification != "" {
		for i, s := range wrap("“"+r.Justification+"”", iw-lw) {
			label := ""
			if i == 0 {
				label = "Agent says"
			}
			l = append(l, kv(label, s, lw))
		}
	}
	l = append(l, kv("Requested", dimStyle.Render(r.Created.Local().Format("15:04:05")+" · "+ago(r.Created)), lw))
	l = append(l, "", countdown(r, iw), "")
	if m.denyNote != nil && m.denyID == r.ID {
		l = append(l, badStyle.Render("Deny")+dimStyle.Render(" · note for the agent (optional):"))
		l = append(l, lipgloss.NewStyle().Foreground(cRed).Render("› ")+m.denyNote.View())
		l = append(l, keyHints("enter", "deny", "esc", "cancel"))
	} else {
		l = append(l, keyHints("y", "approve", "m", "approve & remember", "n", "deny…")+"  "+dimStyle.Render(hintIf(m.modal != nil, "esc later")))
	}
	title := "Approval request"
	right := ""
	if total > 1 {
		right = dimStyle.Render(fmt.Sprintf("%d of %d", idx+1, total))
	}
	color := cYellow
	if !focused {
		color = cGray
	}
	for len(l) < h-2 {
		l = append(l, "")
	}
	return cardBox(title, right, l, w, color)
}

func cardBox(title, right string, lines []string, w int, color lipgloss.Color) string {
	bc := lipgloss.NewStyle().Foreground(color)
	inner := w - 2
	t := " " + title + " "
	rt := ""
	if right != "" {
		rt = " " + right + " "
	}
	fill := max(inner-2-width(t)-width(rt), 0)
	var b strings.Builder
	b.WriteString(bc.Render("╭─") + lipgloss.NewStyle().Bold(true).Foreground(color).Render(t) + bc.Render(strings.Repeat("─", fill)) + rt + bc.Render("─╮") + "\n")
	for _, l := range lines {
		b.WriteString(bc.Render("│") + " " + fit(l, inner-2) + " " + bc.Render("│") + "\n")
	}
	b.WriteString(bc.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}

func (m *Model) alertsView(w, h int) string {
	if len(m.pending) == 0 {
		lines := []string{"", dimStyle.Render(" No pending approval requests."), "",
			dimStyle.Render(" Requests from agents appear here (and as a popup in the other tabs)."),
			dimStyle.Render(" Without an open tussh you get a notification and, in herdr, a popup.")}
		return panel("Alerts", lines, w, h, true, "")
	}
	sel := m.cursor[TabAlerts]
	if w >= wideMin && len(m.pending) > 1 {
		lw := min(max(w*32/100, 30), 44)
		iw := lw - 4
		var rows []string
		for i, r := range m.pending {
			left := fmt.Sprintf("%ds", max(int(time.Until(r.Expires).Seconds()), 0))
			r1 := fit(" "+oneLine(r.Connection), iw-6) + " " + warnStyle.Render(padLeft(left, 4)) + " "
			r2 := "   " + dimStyle.Render(fit(oneLine(r.Command), iw-4)) + " "
			if i == sel {
				r1, r2 = highlightRow(selStyle.Render("›")+r1[1:], iw), highlightRow(r2, iw)
			}
			rows = append(rows, r1, r2)
		}
		left := panel("Pending", rows, lw, h, false, badStyle.Render(fmt.Sprintf("%d", len(m.pending))))
		cw := w - lw
		return hjoin(left, m.alertCard(m.pending[sel], cw, h, sel, len(m.pending), true))
	}
	card := m.alertCard(m.pending[sel], w, 0, sel, len(m.pending), true)
	if len(m.pending) > 1 {
		card += "\n" + dimStyle.Render(" ↑↓ next request")
	}
	return card
}
