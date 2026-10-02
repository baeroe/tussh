package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

// Form field ids, in display order.
const (
	fName = iota
	fHost
	fPort
	fUser
	fDescription
	fTags
	fAuth
	fKeyPath
	fPassphrase
	fPassword
	fLevel
	fTunnels
	numFields
)

var fieldLabels = [numFields]string{"Name", "Host", "Port", "User", "Description", "Tags", "Method", "Key file",
	"Key passphrase", "Password", "Level", "Forwards"}

// formSections start at these fields.
var formSections = map[int]string{fName: "Connection", fAuth: "Authentication", fLevel: "Agent access", fTunnels: "Tunnels"}

type connForm struct {
	orig   *config.Connection
	inputs [numFields]textinput.Model
	auth   string
	level  string
	focus  int
	err    string

	testing    bool
	testGen    int
	testResult string
	testOK     bool

	// key file field: detected keys, inline completion, validation hint
	home       string   // for ~
	sshDir     string   // where keys are detected
	keys       []sshKey // private keys in sshDir (scanned when the field is first focused)
	keysLoaded bool
	keySel     int // highlighted row in the filtered key list, -1 = none
	keyOff     int // first visible row of the key list
	ghost      string
	check      keyCheck
	checkFor   string // value+passphrase state the check was computed for
}

// keyListRows is the maximum number of rows of the detected keys list.
const keyListRows = 6

func newForm(c *config.Connection, home, sshDir string) *connForm {
	f := &connForm{auth: config.AuthKey, level: config.LevelNone, home: home, sshDir: sshDir, keySel: -1}
	for i := range f.inputs {
		ti := textinput.New()
		ti.Prompt = ""
		ti.CharLimit = 512
		ti.Width = 40 // set again when rendering; without a width the placeholder shows only one character
		f.inputs[i] = ti
	}
	f.inputs[fName].Placeholder = "web-prod"
	f.inputs[fHost].Placeholder = "host name or IP"
	f.inputs[fPort].Placeholder = "22"
	f.inputs[fPort].CharLimit = 5
	f.inputs[fUser].Placeholder = "remote user (empty: ssh default)"
	f.inputs[fDescription].Placeholder = "optional, also shown to agents"
	f.inputs[fTags].Placeholder = "comma-separated, e.g. prod, shop"
	f.inputs[fKeyPath].Placeholder = "~/.ssh/id_ed25519"
	// the ghost completion uses textinput's suggestion rendering; its keys are handled by the form
	f.inputs[fKeyPath].ShowSuggestions = true
	f.inputs[fKeyPath].KeyMap.AcceptSuggestion = key.NewBinding(key.WithDisabled())
	f.inputs[fKeyPath].KeyMap.NextSuggestion = key.NewBinding(key.WithDisabled())
	f.inputs[fKeyPath].KeyMap.PrevSuggestion = key.NewBinding(key.WithDisabled())
	f.inputs[fTunnels].Placeholder = "mysql=3307:127.0.0.1:3306, redis=6380:localhost:6379"
	f.inputs[fPassword].EchoMode = textinput.EchoPassword
	f.inputs[fPassphrase].EchoMode = textinput.EchoPassword
	f.inputs[fPassword].Placeholder = "stored in the keychain"
	f.inputs[fPassphrase].Placeholder = "optional, stored in the keychain"
	if c != nil {
		cc := *c
		f.orig = &cc
		f.inputs[fName].SetValue(c.Name)
		f.inputs[fDescription].SetValue(c.Description)
		f.inputs[fTags].SetValue(strings.Join(c.Tags, ", "))
		f.inputs[fHost].SetValue(c.Host)
		if c.Port != 0 {
			f.inputs[fPort].SetValue(strconv.Itoa(c.Port))
		}
		f.inputs[fUser].SetValue(c.User)
		f.inputs[fKeyPath].SetValue(c.KeyPath)
		f.inputs[fTunnels].SetValue(formatTunnels(c.Tunnels))
		f.auth = c.Auth
		f.level = c.Level()
		if c.HasPassword {
			f.inputs[fPassword].Placeholder = "(stored, leave empty to keep)"
		}
		if c.HasPassphrase {
			f.inputs[fPassphrase].Placeholder = "(stored, leave empty to keep)"
		}
	}
	f.setFocus(fName)
	return f
}

// formatTunnels and parseTunnels use the syntax shared with the MCP tool new_connection.
func formatTunnels(ts []config.Tunnel) string { return config.FormatTunnels(ts) }

func parseTunnels(s string) ([]config.Tunnel, error) { return config.ParseTunnels(s) }

func (f *connForm) visible(i int) bool {
	switch i {
	case fPassword:
		return f.auth == config.AuthPassword
	case fKeyPath, fPassphrase:
		return f.auth == config.AuthKey
	}
	return true
}

func (f *connForm) isChoice(i int) bool { return i == fAuth || i == fLevel }

func (f *connForm) setFocus(i int) {
	for j := range f.inputs {
		f.inputs[j].Blur()
	}
	f.focus = i
	if !f.isChoice(i) {
		f.inputs[i].Focus()
	}
	f.keySel, f.keyOff = -1, 0
	if i == fKeyPath && !f.keysLoaded && f.sshDir != "" {
		f.keys, f.keysLoaded = scanKeys(f.sshDir, f.home), true
	}
	f.refreshGhost()
}

// refreshGhost recomputes the inline completion of the key file field (only with the cursor at the end).
func (f *connForm) refreshGhost() {
	in := &f.inputs[fKeyPath]
	f.ghost = ""
	if f.focus == fKeyPath && in.Position() == len([]rune(in.Value())) {
		f.ghost = completePath(in.Value(), f.home)
	}
	if f.ghost == "" {
		in.SetSuggestions(nil)
	} else {
		in.SetSuggestions([]string{in.Value() + f.ghost})
	}
}

// keyList is the detected keys filtered by the field's value.
func (f *connForm) keyList() []sshKey {
	return filterKeys(f.keys, f.inputs[fKeyPath].Value(), f.home)
}

func (f *connForm) moveKeySel(delta int) {
	n := len(f.keyList())
	if n == 0 {
		f.keySel = -1
		return
	}
	switch {
	case f.keySel < 0 && delta > 0:
		f.keySel = 0
	case f.keySel < 0:
		f.keySel = n - 1
	default:
		f.keySel = (f.keySel + delta + n) % n
	}
	if f.keySel < f.keyOff {
		f.keyOff = f.keySel
	}
	if f.keySel >= f.keyOff+keyListRows {
		f.keyOff = f.keySel - keyListRows + 1
	}
}

// setKeyPath replaces the field's value (cursor at the end) and resets the list.
func (f *connForm) setKeyPath(v string) {
	f.inputs[fKeyPath].SetValue(v)
	f.inputs[fKeyPath].CursorEnd()
	f.keySel, f.keyOff = -1, 0
	f.refreshGhost()
}

// keyFieldKey handles the key file field's own keys; ok=false passes the key on.
func (f *connForm) keyFieldKey(k tea.KeyMsg) (ok bool) {
	switch k.String() {
	case "ctrl+n":
		f.moveKeySel(1)
		return true
	case "ctrl+p":
		f.moveKeySel(-1)
		return true
	case "enter":
		if l := f.keyList(); f.keySel >= 0 && f.keySel < len(l) {
			f.setKeyPath(l[f.keySel].Display)
			return true
		}
	case "esc":
		if f.keySel >= 0 {
			f.keySel = -1
			return true
		}
	case "right", "ctrl+f":
		in := &f.inputs[fKeyPath]
		if f.ghost != "" && in.Position() == len([]rune(in.Value())) {
			f.setKeyPath(in.Value() + f.ghost)
			return true
		}
	}
	return false
}

// keyCheck returns the (cached) validation hint of the key file field.
func (f *connForm) keyCheck() keyCheck {
	hasPP := f.inputs[fPassphrase].Value() != "" || (f.orig != nil && f.orig.HasPassphrase)
	id := f.inputs[fKeyPath].Value() + "\x00" + strconv.FormatBool(hasPP)
	if id != f.checkFor {
		f.check, f.checkFor = checkKeyFile(f.inputs[fKeyPath].Value(), f.home, hasPP), id
	}
	return f.check
}

func (f *connForm) move(delta int) {
	i := f.focus
	for {
		i = (i + delta + numFields) % numFields
		if f.visible(i) {
			break
		}
	}
	f.setFocus(i)
}

func (f *connForm) cycle(delta int) {
	switch f.focus {
	case fAuth:
		if f.auth == config.AuthKey {
			f.auth = config.AuthPassword
		} else {
			f.auth = config.AuthKey
		}
	case fLevel:
		idx := 0
		for i, l := range config.Levels {
			if l == f.level {
				idx = i
			}
		}
		f.level = config.Levels[(idx+delta+len(config.Levels))%len(config.Levels)]
	}
}

func (m *Model) formKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	if f.focus == fKeyPath && f.keyFieldKey(k) {
		return m, nil
	}
	switch k.String() {
	case "esc":
		m.form = nil
		m.flash("cancelled")
		return m, nil
	case "ctrl+s":
		return m, m.saveFormCmd()
	case "ctrl+t":
		return m, m.testForm()
	case "tab", "down":
		f.move(1)
		return m, nil
	case "shift+tab", "up":
		f.move(-1)
		return m, nil
	case "enter":
		if f.focus == fTunnels {
			return m, m.saveFormCmd()
		}
		f.move(1)
		return m, nil
	}
	if f.isChoice(f.focus) {
		switch k.String() {
		case "left", "h":
			f.cycle(-1)
		case "right", "l", " ", "space":
			f.cycle(1)
		}
		return m, nil
	}
	var cmd tea.Cmd
	before := f.inputs[f.focus].Value()
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(k)
	if f.focus == fKeyPath {
		if f.inputs[fKeyPath].Value() != before {
			f.keySel, f.keyOff = -1, 0
		}
		f.refreshGhost()
	}
	return m, cmd
}

// build turns the form into a connection (not saved) plus the secrets typed in it.
func (f *connForm) build() (c config.Connection, password, passphrase string, err error) {
	val := func(i int) string { return strings.TrimSpace(f.inputs[i].Value()) }
	if f.orig != nil {
		c = *f.orig
	}
	c.Name, c.Description, c.Host, c.User = val(fName), val(fDescription), val(fHost), val(fUser)
	c.Tags = config.ParseTags(val(fTags))
	c.Port = 0
	if p := val(fPort); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil {
			return c, "", "", fmt.Errorf("port: must be a number")
		}
		c.Port = n
	}
	c.Auth, c.AccessLevel = f.auth, f.level
	c.KeyPath = ""
	if c.Auth == config.AuthKey {
		c.KeyPath = val(fKeyPath)
	}
	ts, terr := parseTunnels(val(fTunnels))
	if terr != nil {
		return c, "", "", terr
	}
	c.Tunnels = ts
	if c.ID == "" {
		c.ID = config.NewID()
	}
	if c.Auth == config.AuthPassword {
		password = f.inputs[fPassword].Value()
	} else {
		passphrase = f.inputs[fPassphrase].Value()
	}
	if err := c.Validate(); err != nil {
		return c, "", "", err
	}
	return c, password, passphrase, nil
}

// testForm runs a real, non-interactive login with the form's values (only when the user asks).
func (m *Model) testForm() tea.Cmd {
	f := m.form
	c, password, passphrase, err := f.build()
	if err != nil {
		f.testResult, f.testOK, f.testing = err.Error(), false, false
		return nil
	}
	if f.orig == nil {
		c.HasPassword, c.HasPassphrase = false, false
	}
	if c.Auth == config.AuthPassword && password == "" && !c.HasPassword {
		f.testResult, f.testOK = "enter the password first", false
		return nil
	}
	f.testGen++
	f.testing, f.testResult, f.err = true, "", ""
	gen, test := f.testGen, m.opts.TestConn
	secret := password + passphrase
	return func() tea.Msg { return testConnMsg{gen: gen, err: test(c, secret)} }
}

// saveFormCmd saves and, once the form is closed, probes the (possibly new) host.
func (m *Model) saveFormCmd() tea.Cmd {
	m.saveForm()
	if m.form == nil && !m.opts.NoTick {
		return m.checkReach(false)
	}
	return nil
}

// saveForm validates, stores secrets in the keyring and writes connections.json.
func (m *Model) saveForm() {
	f := m.form
	c, password, passphrase, err := f.build()
	if err != nil {
		f.err = err.Error()
		return
	}
	if c.Auth == config.AuthPassword && password == "" && !c.HasPassword {
		f.err = "password: required for password auth (it is stored in the keychain)"
		return
	}
	for _, o := range m.store.Connections {
		if o.Name == c.Name && o.ID != c.ID {
			f.err = fmt.Sprintf("name: %q is already used", c.Name)
			return
		}
	}
	kr := m.opts.Keyring
	if c.Auth == config.AuthPassword {
		if password != "" {
			if err := kr.Set(secrets.Account(c.ID, secrets.KindPassword), password); err != nil {
				f.err = "keychain: " + err.Error()
				return
			}
			c.HasPassword = true
		}
		_ = kr.Delete(secrets.Account(c.ID, secrets.KindPassphrase))
		c.HasPassphrase = false
	} else {
		if passphrase != "" {
			if err := kr.Set(secrets.Account(c.ID, secrets.KindPassphrase), passphrase); err != nil {
				f.err = "keychain: " + err.Error()
				return
			}
			c.HasPassphrase = true
		}
		_ = kr.Delete(secrets.Account(c.ID, secrets.KindPassword))
		c.HasPassword = false
	}
	c.NeedsSetup = false // saved by the user: an agent-created connection is set up now
	if err := m.mutateStore(func(s *config.Store) error { _, err := s.Upsert(c); return err }); err != nil {
		f.err = err.Error()
		return
	}
	m.form = nil
	m.refreshTunnels()
	m.selectByID(c.ID)
	m.flash("saved %s (agent access %s)", c.Name, c.AccessLevel)
}

// --- rendering ----------------------------------------------------------------------------

func choice(opts []string, cur string, focused bool) string {
	var parts []string
	for _, o := range opts {
		switch {
		case o == cur && focused:
			parts = append(parts, selStyle.Render("● "+o))
		case o == cur:
			parts = append(parts, boldStyle.Render("● "+o))
		default:
			parts = append(parts, dimStyle.Render("○ "+o))
		}
	}
	return strings.Join(parts, "  ")
}

// formBox renders the form as a modal of at most w x h cells; it scrolls to keep the focused field visible.
func (m *Model) formBox(w, h int) string {
	f := m.form
	fw := min(w-2, 80)
	iw := fw - 4
	const lw = 16
	inW := max(iw-2-lw-1, 10)
	var lines []string
	focusLine, focusEnd := 0, 0
	for i := 0; i < numFields; i++ {
		if !f.visible(i) {
			continue
		}
		if sec, ok := formSections[i]; ok {
			if i != fName {
				lines = append(lines, "")
			}
			lines = append(lines, accentStyle.Bold(true).Render(sec))
		}
		label := fit(fieldLabels[i], lw)
		mark := "  "
		if i == f.focus {
			label = selStyle.Render(label)
			mark = selStyle.Render("› ")
			focusLine = len(lines)
		} else {
			label = labelStyle.Render(label)
		}
		var v string
		switch i {
		case fAuth:
			v = choice([]string{config.AuthKey, config.AuthPassword}, f.auth, i == f.focus)
		case fLevel:
			v = choice(config.Levels, f.level, i == f.focus)
		default:
			f.inputs[i].Width = inW - 1
			v = ansi.Truncate(f.inputs[i].View(), inW, "") // the ghost completion may run past the width
		}
		lines = append(lines, mark+label+v)
		indent := strings.Repeat(" ", lw+2)
		switch i {
		case fKeyPath:
			hint := f.keyCheck().render()
			if i == f.focus && f.ghost != "" && f.keyCheck().level == checkBad {
				// still typing: show what → completes to instead of "file not found"
				hint = dimStyle.Render("→ completes to " + f.inputs[fKeyPath].Value() + f.ghost)
			}
			lines = append(lines, indent+ansi.Truncate(hint, inW, "…"))
			if i == f.focus {
				for _, l := range f.keyListView(inW) {
					lines = append(lines, indent+l)
				}
			}
		case fLevel:
			lines = append(lines, strings.Repeat(" ", lw+2)+badge(f.level, true))
			for _, s := range wrap(levelExplain(f.level), inW) {
				lines = append(lines, strings.Repeat(" ", lw+2)+dimStyle.Render(s))
			}
		case fTunnels:
			lines = append(lines, strings.Repeat(" ", lw+2)+dimStyle.Render("name=[bind:]local:host:port, comma-separated"))
		}
		if i == f.focus {
			focusEnd = len(lines) - 1
		}
	}
	var foot []string
	foot = append(foot, "")
	switch {
	case f.err != "":
		foot = append(foot, badStyle.Render("✗ "+f.err))
	case f.testing:
		foot = append(foot, warnStyle.Render("◌ testing the connection …"))
	case f.testResult != "" && f.testOK:
		foot = append(foot, goodStyle.Render("✓ "+f.testResult))
	case f.testResult != "":
		foot = append(foot, badStyle.Render("✗ test failed: "+f.testResult))
	default:
		foot = append(foot, dimStyle.Render("Secrets go to the keychain; empty secret fields keep the stored value."))
	}
	foot = append(foot, keyHints("ctrl+s", "save", "ctrl+t", "test connection", "esc", "cancel"))
	room := h - 2 - len(foot)
	if len(lines) > room && room > 3 {
		start := max(0, focusLine-room/2)
		if focusEnd >= start+room { // keep the focused field's hint and list visible
			start = min(focusEnd-room+1, focusLine)
		}
		start = min(start, len(lines)-room)
		lines = lines[start : start+room]
	}
	title := "New connection"
	if f.orig != nil {
		title = "Edit " + f.orig.Name
	}
	return modalBox(title, append(lines, foot...), fw, cAccent)
}

// keyListView renders the detected keys below the key file field (at most keyListRows rows, scrolling).
func (f *connForm) keyListView(w int) []string {
	l := f.keyList()
	if len(l) == 0 {
		if len(f.keys) == 0 && f.inputs[fKeyPath].Value() == "" {
			return []string{dimStyle.Render("no private keys found in " + tildeHome(f.sshDir, f.home))}
		}
		return nil
	}
	head := "detected keys"
	if len(l) > keyListRows {
		head += fmt.Sprintf(" %d–%d of %d", f.keyOff+1, min(f.keyOff+keyListRows, len(l)), len(l))
	}
	hint := keyHints("ctrl+n/p", "select", "enter", "use")
	if f.keySel < 0 {
		hint = keyHints("ctrl+n", "select")
	}
	out := []string{dimStyle.Render(head) + "  " + hint}
	pw, tw := 0, 0
	for _, k := range l {
		pw, tw = max(pw, width(k.Display)), max(tw, width(k.Type))
	}
	pw = min(pw, max(w*45/100, 12))
	for i := f.keyOff; i < len(l) && i < f.keyOff+keyListRows; i++ {
		k := l[i]
		row := ellipsizeMiddle(k.Display, pw)
		row = fit(row, pw) + "  " + fit(k.Type, tw+2)
		if k.Comment != "" {
			row += dimStyle.Render(k.Comment)
		}
		if k.Encrypted {
			if k.Comment != "" {
				row += "  "
			}
			row += warnStyle.Render("passphrase")
		}
		if i == f.keySel {
			out = append(out, highlightRow(selStyle.Render("› ")+row, w))
		} else {
			out = append(out, "  "+row)
		}
	}
	return out
}
