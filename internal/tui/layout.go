package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/baeroe/tussh/internal/config"
)

// Colors come from the terminal's 16-color ANSI palette, so tussh follows the terminal theme.
var (
	cRed     = lipgloss.Color("1")
	cGreen   = lipgloss.Color("2")
	cYellow  = lipgloss.Color("3")
	cBlue    = lipgloss.Color("4")
	cMagenta = lipgloss.Color("5")
	cCyan    = lipgloss.Color("6")
	cGray    = lipgloss.Color("8")
	cWhite   = lipgloss.Color("15")

	cAccent = cCyan

	dimStyle    = lipgloss.NewStyle().Faint(true)
	boldStyle   = lipgloss.NewStyle().Bold(true)
	accentStyle = lipgloss.NewStyle().Foreground(cAccent)
	selStyle    = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	goodStyle   = lipgloss.NewStyle().Foreground(cGreen)
	badStyle    = lipgloss.NewStyle().Foreground(cRed)
	warnStyle   = lipgloss.NewStyle().Foreground(cYellow)
	blueStyle   = lipgloss.NewStyle().Foreground(cBlue)
	keyStyle    = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	labelStyle  = lipgloss.NewStyle().Faint(true)
	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Reverse(true).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Padding(0, 1)
	alertChip   = lipgloss.NewStyle().Bold(true).Foreground(cWhite).Background(cRed).Padding(0, 1)
	appName     = lipgloss.NewStyle().Bold(true).Foreground(cMagenta)
	codeStyle   = lipgloss.NewStyle().Foreground(cWhite).Bold(true)
)

// selectedBG is the SGR sequence of the selected-row background (ANSI bright black).
const selectedBG = "\x1b[100m"

// --- width-safe string helpers ---------------------------------------------------------

// width is the display width (grapheme aware, ANSI escapes ignored).
func width(s string) int { return ansi.StringWidth(s) }

// fit truncates s to w cells (with an ellipsis) and pads it with spaces to exactly w cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if width(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	if d := w - width(s); d > 0 {
		s += strings.Repeat(" ", d)
	}
	return s
}

// padLeft right-aligns s in w cells.
func padLeft(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if width(s) > w {
		return ansi.Truncate(s, w, "…")
	}
	return strings.Repeat(" ", w-width(s)) + s
}

// ellipsizeMiddle shortens plain text to w cells by cutting out the middle (good for paths).
func ellipsizeMiddle(s string, w int) string {
	if width(s) <= w || w < 5 {
		return ansi.Truncate(s, w, "…")
	}
	r := []rune(s)
	keepR := (w - 1) * 2 / 3
	keepL := w - 1 - keepR
	return string(r[:keepL]) + "…" + string(r[len(r)-keepR:])
}

// tildify shows paths under $HOME with ~.
func tildify(p string) string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" || h == "/" {
		return p
	}
	if p == h {
		return "~"
	}
	if strings.HasPrefix(p, h+string(filepath.Separator)) {
		return "~" + p[len(h):]
	}
	return p
}

// san makes external text (commands, output, notes) safe to print: ANSI escapes are removed, tabs become
// spaces and other control characters are shown as "?". Newlines are kept.
func san(s string) string {
	s = ansi.Strip(s)
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f || (r >= 0x80 && r < 0xa0) }) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// oneLine is san plus all whitespace collapsed (for table cells).
func oneLine(s string) string { return strings.Join(strings.Fields(san(s)), " ") }

// wrap breaks plain text into lines of at most w cells (on spaces when possible).
func wrap(s string, w int) []string {
	if w <= 0 {
		return nil
	}
	s = san(s)
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			for width(word) > w {
				if line != "" {
					out = append(out, line)
					line = ""
				}
				cut := ansi.Truncate(word, w, "")
				out = append(out, cut)
				word = string([]rune(word)[len([]rune(cut)):])
			}
			switch {
			case line == "":
				line = word
			case width(line)+1+width(word) <= w:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
		}
		out = append(out, line)
	}
	return out
}

// hardWrap breaks text at w cells, preferring the last space of a line; spacing is kept exactly
// (used for commands, which must be shown as they will run, and for output).
func hardWrap(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	var out []string
	for _, para := range strings.Split(san(s), "\n") {
		r := []rune(para)
		if len(r) == 0 {
			out = append(out, "")
			continue
		}
		for len(r) > 0 {
			cut := []rune(ansi.Truncate(string(r), w, ""))
			n := max(len(cut), 1)
			if n < len(r) {
				if sp := lastSpace(cut); sp > n/2 {
					n = sp + 1
				}
			}
			out = append(out, string(r[:n]))
			r = r[n:]
		}
	}
	return out
}

func lastSpace(r []rune) int {
	for i := len(r) - 1; i >= 0; i-- {
		if r[i] == ' ' {
			return i
		}
	}
	return -1
}

// highlightRow renders a selected row with a background over the full width.
func highlightRow(line string, w int) string {
	line = fit(line, w)
	line = strings.ReplaceAll(line, "\x1b[0m", "\x1b[0m"+selectedBG)
	line = strings.ReplaceAll(line, "\x1b[m", "\x1b[m"+selectedBG)
	return selectedBG + line + "\x1b[0m"
}

// --- icons -----------------------------------------------------------------------------
// Only characters whose width is the same in every width table are used: emoji with default emoji
// presentation (always 2 cells) and plain symbols (1 cell). Icons are padded to 2 cells.

func icon2(s string) string { return fit(s, 2) }

func levelIcon(l string) string {
	switch l {
	case config.LevelReadOnly:
		return "👀"
	case config.LevelApproveEach:
		return "✋"
	case config.LevelTrusted:
		return "✓"
	}
	return "⛔"
}

func levelColor(l string) lipgloss.Style {
	switch l {
	case config.LevelReadOnly:
		return blueStyle
	case config.LevelApproveEach:
		return warnStyle
	case config.LevelTrusted:
		return goodStyle
	}
	return dimStyle
}

// levelShort is the badge text in the list.
func levelShort(l string) string {
	switch l {
	case config.LevelReadOnly:
		return "read-only"
	case config.LevelApproveEach:
		return "approve"
	case config.LevelTrusted:
		return "trusted"
	}
	return "none"
}

// badge is icon + text, colored by level. full uses the level's full name.
func badge(l string, full bool) string {
	t := levelShort(l)
	if full {
		t = l
	}
	return icon2(levelIcon(l)) + " " + levelColor(l).Render(t)
}

func levelExplain(l string) string {
	switch l {
	case config.LevelReadOnly:
		return "Read-only commands run automatically; anything else waits for your approval."
	case config.LevelApproveEach:
		return "Every agent command waits for your approval."
	case config.LevelTrusted:
		return "Commands run automatically; sensitive ones (secrets, deleting, …) still ask you."
	}
	return "Hidden from agents: they cannot see or use this connection."
}

// --- time formatting ---------------------------------------------------------------------

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func shortDur(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case ms <= 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("%dms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func clock(t time.Time) string {
	t = t.Local()
	y1, m1, d1 := t.Date()
	y2, m2, d2 := time.Now().Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04:05")
	}
	return t.Format("01-02 15:04")
}

// --- panels and overlays -------------------------------------------------------------------

// panel draws a rounded box of exactly w x h cells with title (and optional right title) in the top border.
// lines beyond h-2 are cut; each line is fitted to the inner width.
func panel(title string, lines []string, w, h int, focused bool, right string) string {
	if w < 6 || h < 2 {
		return ""
	}
	bc := lipgloss.NewStyle().Foreground(cGray)
	tc := boldStyle
	if focused {
		bc = lipgloss.NewStyle().Foreground(cAccent)
		tc = selStyle
	}
	inner := w - 2
	t := ""
	if title != "" {
		t = " " + ansi.Truncate(title, inner-4, "…") + " "
	}
	rt := ""
	if right != "" {
		rt = " " + right + " "
		if 2+width(t)+width(rt) > inner {
			rt = ""
		}
	}
	fill := inner - 2 - width(t) - width(rt)
	if fill < 0 {
		fill = 0
	}
	var b strings.Builder
	b.WriteString(bc.Render("╭─") + tc.Render(t) + bc.Render(strings.Repeat("─", fill)) + rt + bc.Render("─╮") + "\n")
	for i := 0; i < h-2; i++ {
		l := ""
		if i < len(lines) {
			l = lines[i]
		}
		b.WriteString(bc.Render("│") + " " + fit(l, inner-2) + " " + bc.Render("│") + "\n")
	}
	b.WriteString(bc.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}

// hjoin puts blocks side by side (each block has fixed-width lines).
func hjoin(blocks ...string) string { return lipgloss.JoinHorizontal(lipgloss.Top, blocks...) }

// overlay draws fg centered over bg (w x h); the background is dimmed and stripped of colors.
func overlay(bg, fg string, w, h int) string {
	src := strings.Split(bg, "\n")
	plain := make([]string, h)
	out := make([]string, h)
	for i := 0; i < h; i++ {
		l := ""
		if i < len(src) {
			l = src[i]
		}
		plain[i] = fit(ansi.Strip(l), w)
		out[i] = dimStyle.Render(plain[i])
	}
	fl := strings.Split(fg, "\n")
	fw := 0
	for _, l := range fl {
		fw = max(fw, width(l))
	}
	fw = min(fw, w)
	x := max(0, (w-fw)/2)
	y := max(0, (h-len(fl))/2)
	for i, l := range fl {
		row := y + i
		if row >= h {
			break
		}
		left := fit(ansi.Truncate(plain[row], x, ""), x)
		right := padLeft(ansi.TruncateLeft(plain[row], x+fw, ""), w-x-fw)
		out[row] = dimStyle.Render(left) + fit(l, fw) + dimStyle.Render(right)
	}
	return strings.Join(out, "\n")
}

// modalBox draws a bordered box for overlays.
func modalBox(title string, lines []string, w int, color lipgloss.Color) string {
	h := len(lines) + 2
	bc := lipgloss.NewStyle().Foreground(color)
	inner := w - 2
	t := " " + title + " "
	fill := inner - 1 - width(t)
	if fill < 0 {
		fill = 0
	}
	var b strings.Builder
	b.WriteString(bc.Render("╭─") + lipgloss.NewStyle().Bold(true).Foreground(color).Render(t) + bc.Render(strings.Repeat("─", fill)+"╮") + "\n")
	for i := 0; i < h-2; i++ {
		b.WriteString(bc.Render("│") + " " + fit(lines[i], inner-2) + " " + bc.Render("│") + "\n")
	}
	b.WriteString(bc.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}

// keyHints renders "k desc · k desc".
func keyHints(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+dimStyle.Render(pairs[i+1]))
	}
	return strings.Join(parts, "  ")
}

// kv renders a label column of width lw and a value.
func kv(label, value string, lw int) string {
	return labelStyle.Render(fit(label, lw)) + value
}
