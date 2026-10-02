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

// Form field ids.
const (
	fName = iota
	fGroup
	fDescription
	fHost
	fPort
	fUser
	fAuth
	fPassword
	fKeyPath
	fPassphrase
	fLevel
	fTunnels
	numFields
)

var fieldLabels = [numFields]string{"Name", "Group", "Description", "Host", "Port", "User", "Auth", "Password",
	"Key file", "Key passphrase", "Agent access", "Tunnels"}

type connForm struct {
	orig   *config.Connection
	inputs [numFields]textinput.Model
	auth   string
	level  string
	focus  int
	err    string
}

func newForm(c *config.Connection) *connForm {
	f := &connForm{auth: config.AuthKey, level: config.LevelNone}
	for i := range f.inputs {
		ti := textinput.New()
		ti.Prompt = ""
		ti.CharLimit = 512
		f.inputs[i] = ti
	}
	f.inputs[fPort].Placeholder = "22"
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
		f.inputs[fGroup].SetValue(c.Group)
		f.inputs[fDescription].SetValue(c.Description)
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
		m.saveForm()
		return m, nil
	case "tab", "down":
		f.move(1)
		return m, nil
	case "shift+tab", "up":
		f.move(-1)
		return m, nil
	case "enter":
		if f.focus == fTunnels {
			m.saveForm()
			return m, nil
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

// saveForm validates, stores secrets in the keyring and writes connections.json.
func (m *Model) saveForm() {
	f := m.form
	val := func(i int) string { return strings.TrimSpace(f.inputs[i].Value()) }
	c := config.Connection{}
	if f.orig != nil {
		c = *f.orig
	}
	c.Name, c.Group, c.Description, c.Host, c.User = val(fName), val(fGroup), val(fDescription), val(fHost), val(fUser)
	c.Port = 0
	if p := val(fPort); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			f.err = "port: must be a number"
			return
		}
		c.Port = n
	}
	c.Auth, c.AccessLevel = f.auth, f.level
	c.KeyPath = ""
	if c.Auth == config.AuthKey {
		c.KeyPath = val(fKeyPath)
	}
	ts, err := parseTunnels(val(fTunnels))
	if err != nil {
		f.err = err.Error()
		return
	}
	c.Tunnels = ts
	if c.ID == "" {
		c.ID = config.NewID()
	}
	password := f.inputs[fPassword].Value()
	passphrase := f.inputs[fPassphrase].Value()
	if c.Auth == config.AuthPassword && password == "" && !c.HasPassword {
		f.err = "password: required for password auth (it is stored in the keychain)"
		return
	}
	if err := c.Validate(); err != nil {
		f.err = err.Error()
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
