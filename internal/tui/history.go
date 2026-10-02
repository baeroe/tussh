package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/audit"
)

var decisionFilters = []string{"", audit.Auto, audit.Approved, audit.Denied, audit.Timeout, audit.Blocked, audit.Created}

func decisionIcon(e audit.Entry) string {
	switch e.Decision {
	case audit.Auto:
		return goodStyle.Render(icon2("✓"))
	case audit.Approved:
		return icon2("👍")
	case audit.Denied:
		return badStyle.Render(icon2("✗"))
	case audit.Timeout:
		return icon2("⌛")
	case audit.Blocked:
		return icon2("⛔")
	case audit.Created:
		return accentStyle.Render(icon2("+"))
	}
	return icon2("?")
}

func (m *Model) filteredHistory() []audit.Entry {
	q := strings.ToLower(m.query[TabHistory])
	var out []audit.Entry
	for _, e := range m.history {
		if m.histConn != "" && e.Connection != m.histConn {
			continue
		}
		if m.histDecision != "" && e.Decision != m.histDecision {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Command+"\x00"+e.Connection+"\x00"+e.Justification+"\x00"+e.Agent), q) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (m *Model) historyConnections() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range m.history {
		if e.Connection != "" && !seen[e.Connection] {
			seen[e.Connection] = true
			out = append(out, e.Connection)
		}
	}
	sort.Strings(out)
	return out
}

func cycle(list []string, cur string) string {
	for i, x := range list {
		if x == cur {
			return list[(i+1)%len(list)]
		}
	}
	return list[0]
}

func (m *Model) historyKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		m.historyOpen = !m.historyOpen
	case "c":
		m.histConn = cycle(append([]string{""}, m.historyConnections()...), m.histConn)
		m.cursor[TabHistory] = 0
	case "d":
		m.histDecision = cycle(decisionFilters, m.histDecision)
		m.cursor[TabHistory] = 0
	case "esc":
		m.histConn, m.histDecision, m.historyOpen = "", "", false
	}
	m.clampCursors()
	return m, nil
}

func exitText(e audit.Entry) string {
	switch {
	case e.TimedOut:
		return warnStyle.Render("t/o")
	case e.ExitCode == nil:
		return dimStyle.Render("—")
	case *e.ExitCode == 0:
		return goodStyle.Render("0")
	}
	return badStyle.Render(fmt.Sprintf("%d", *e.ExitCode))
}

func (m *Model) historyTable(iw, ih int, entries []audit.Entry) []string {
	connW := 14
	if iw < 70 {
		connW = 10
	}
	cmdW := iw - 2 - 1 - 11 - 1 - connW - 1 - 1 - 4 - 1 - 7
	header := dimStyle.Render(fit("", 3) + fit("time", 12) + fit("connection", connW+1) + fit("command", cmdW+1) + padLeft("exit", 4) + " " + padLeft("took", 7))
	lines := []string{header}
	sel := m.cursor[TabHistory]
	start := 0
	rows := ih - 1
	if m.query[TabHistory] != "" || m.searching {
		rows -= 2
	}
	if sel >= rows {
		start = sel - rows + 1
	}
	for i := start; i < len(entries) && i < start+rows; i++ {
		e := entries[i]
		row := decisionIcon(e) + " " + dimStyle.Render(fit(clock(e.Time), 11)) + " " + fit(oneLine(e.Connection), connW) + " " +
			fit(oneLine(e.Command), cmdW) + " " + padLeft(exitText(e), 4) + " " + dimStyle.Render(padLeft(shortDur(e.DurationMS), 7))
		if i == sel {
			row = highlightRow(row, iw)
		}
		lines = append(lines, row)
	}
	if len(entries) == 0 {
		lines = append(lines, "", dimStyle.Render(" No entries."))
	}
	if m.searching {
		for len(lines) < ih-1 {
			lines = append(lines, "")
		}
		lines = append(lines[:ih-1], m.search.View())
	} else if q := m.query[TabHistory]; q != "" {
		for len(lines) < ih-1 {
			lines = append(lines, "")
		}
		lines = append(lines[:ih-1], accentStyle.Render("/"+q)+dimStyle.Render("  esc clears"))
	}
	return lines
}

func (m *Model) historyDetail(e audit.Entry, dw int) []string {
	const lw = 13
	var l []string
	add := func(label, v string) {
		if v == "" {
			return
		}
		for i, s := range wrap(v, dw-lw) {
			if i > 0 {
				label = ""
			}
			l = append(l, kv(label, s, lw))
		}
	}
	l = append(l, decisionIcon(e)+" "+boldStyle.Render(e.Decision)+dimStyle.Render("  "+e.Time.Local().Format("2006-01-02 15:04:05")))
	l = append(l, "")
	for i, s := range hardWrap(e.Command, dw-2) {
		p := "  "
		if i == 0 {
			p = warnStyle.Bold(true).Render("$ ")
		}
		l = append(l, p+highlightCommand(s, i == 0))
	}
	l = append(l, "")
	add("Connection", oneLine(e.Connection)+"  "+levelColor(e.AccessLevel).Render(e.AccessLevel))
	add("Agent", e.Agent)
	add("Decided by", e.DecidedBy)
	add("Why", strings.Join(e.Reasons, "; "))
	add("Agent says", e.Justification)
	add("Note", e.Note)
	add("Error", e.Error)
	if e.ExitCode != nil || e.TimedOut {
		took := shortDur(e.DurationMS)
		if took != "" {
			took = dimStyle.Render("  in " + took)
		}
		l = append(l, kv("Exit", exitText(e)+took, lw))
	}
	if e.Stdout != "" || e.Stderr != "" {
		title := "Output"
		if e.OutputClipped {
			title += dimStyle.Render("  (clipped)")
		}
		l = append(l, "", boldStyle.Render(title))
		if e.Stdout != "" {
			for _, s := range hardWrap(strings.TrimRight(e.Stdout, "\n"), dw-2) {
				l = append(l, dimStyle.Render("│ ")+s)
			}
		}
		if e.Stderr != "" {
			for _, s := range hardWrap(strings.TrimRight(e.Stderr, "\n"), dw-2) {
				l = append(l, badStyle.Render("│ ")+s)
			}
		}
	} else if e.ExitCode != nil {
		l = append(l, "", dimStyle.Render("No output recorded."))
	}
	return l
}

func (m *Model) historyView(w, h int) string {
	entries := m.filteredHistory()
	var chips []string
	if m.histConn != "" {
		chips = append(chips, "conn:"+m.histConn)
	}
	if m.histDecision != "" {
		chips = append(chips, m.histDecision)
	}
	right := dimStyle.Render(fmt.Sprintf("%d", len(entries)))
	if len(chips) > 0 {
		right = accentStyle.Render(strings.Join(chips, " · ")) + dimStyle.Render(fmt.Sprintf(" · %d", len(entries)))
	}
	if len(m.history) == 0 {
		return panel("History", []string{"", dimStyle.Render(" No agent requests yet.")}, w, h, true, "")
	}
	var sel *audit.Entry
	if len(entries) > 0 {
		e := entries[m.cursor[TabHistory]]
		sel = &e
	}
	if w >= wideMin {
		lw := w * 60 / 100
		rw := w - lw
		var dl []string
		if sel != nil {
			dl = m.historyDetail(*sel, rw-4)
		}
		return hjoin(panel("History", m.historyTable(lw-4, h-2, entries), lw, h, true, right), panel("Details", dl, rw, h, false, ""))
	}
	if m.historyOpen && sel != nil {
		return panel("Details", m.historyDetail(*sel, w-4), w, h, true, dimStyle.Render("enter back"))
	}
	return panel("History", m.historyTable(w-4, h-2, entries), w, h, true, right)
}
