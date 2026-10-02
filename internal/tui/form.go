package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

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
}

func newForm(c *config.Connection) *connForm {
	f := &connForm{auth: config.AuthKey, level: config.LevelNone}
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
	f.inputs[fKeyPath].Placeholder = "~/.ssh/id_ed25519 (empty: ssh defaults / agent)"
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

func formatTunnels(ts []config.Tunnel) string {
	var parts []string
	for _, t := range ts {
		s := fmt.Sprintf("%s=%d:%s:%d", t.Name, t.Local, t.RemoteHost, t.RemotePort)
		if t.Bind != "" && t.Bind != "127.0.0.1" {
			s = fmt.Sprintf("%s=%s:%d:%s:%d", t.Name, t.Bind, t.Local, t.RemoteHost, t.RemotePort)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// parseTunnels parses "name=[bind:]local:host:port, ...".
func parseTunnels(s string) ([]config.Tunnel, error) {
	var out []config.Tunnel
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, spec, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("tunnel %q: use name=local:host:port", part)
		}
		f := strings.Split(spec, ":")
		var t config.Tunnel
		t.Name = strings.TrimSpace(name)
		if len(f) == 4 {
			t.Bind, f = f[0], f[1:]
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("tunnel %q: use name=local:host:port", part)
		}
		var err1, err2 error
		t.Local, err1 = strconv.Atoi(f[0])
		t.RemoteHost = f[1]
		t.RemotePort, err2 = strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("tunnel %q: ports must be numbers", part)
		}
		out = append(out, t)
	}
	return out, nil
}

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
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(k)
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
	if _, err := m.store.Upsert(c); err != nil {
		f.err = err.Error()
		return
	}
	if err := m.store.Save(); err != nil {
		f.err = "save: " + err.Error()
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
	focusLine := 0
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
			v = f.inputs[i].View()
		}
		lines = append(lines, mark+label+v)
		switch i {
		case fLevel:
			lines = append(lines, strings.Repeat(" ", lw+2)+badge(f.level, true))
			for _, s := range wrap(levelExplain(f.level), inW) {
				lines = append(lines, strings.Repeat(" ", lw+2)+dimStyle.Render(s))
			}
		case fTunnels:
			lines = append(lines, strings.Repeat(" ", lw+2)+dimStyle.Render("name=[bind:]local:host:port, comma-separated"))
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
		start = min(start, len(lines)-room)
		lines = lines[start : start+room]
	}
	title := "New connection"
	if f.orig != nil {
		title = "Edit " + f.orig.Name
	}
	return modalBox(title, append(lines, foot...), fw, cAccent)
}
