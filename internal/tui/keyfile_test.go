package tui

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// keygen creates a key pair with ssh-keygen (the test is skipped without it).
func keygen(t *testing.T, path, typ, pass, comment string) {
	t.Helper()
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found")
	}
	args := []string{"-q", "-t", typ, "-N", pass, "-C", comment, "-f", path}
	if typ == "rsa" {
		args = append(args, "-b", "2048")
	}
	if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
}

// keyHome builds a fake home with .ssh: id_ed25519 (+.pub), id_rsa (no .pub), enc_key (encrypted, +.pub),
// and files that are not private keys.
func keyHome(t *testing.T, home string) string {
	t.Helper()
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(ssh, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(home, "Documents"), 0o700)
	keygen(t, filepath.Join(ssh, "id_ed25519"), "ed25519", "", "me@test")
	keygen(t, filepath.Join(ssh, "id_rsa"), "rsa", "", "rsa@test")
	os.Remove(filepath.Join(ssh, "id_rsa.pub"))
	keygen(t, filepath.Join(ssh, "enc_key"), "ed25519", "s3cret", "enc@test")
	for name, body := range map[string]string{
		"config":          "Host *\n  IdentityFile ~/.ssh/id_ed25519\n",
		"known_hosts":     "example.com ssh-ed25519 AAAA\n",
		"known_hosts.old": "",
		"authorized_keys": "ssh-ed25519 AAAA x\n",
		"notes.txt":       "-----BEGIN CERTIFICATE-----\n",
		"public_copy":     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK me@test\n",
	} {
		os.WriteFile(filepath.Join(ssh, name), []byte(body), 0o600)
	}
	// a socket (agent-like); short paths only, so it is best effort
	if l, err := net.Listen("unix", filepath.Join(ssh, "s")); err == nil {
		t.Cleanup(func() { l.Close() })
	}
	return ssh
}

func TestScanKeys(t *testing.T) {
	home := t.TempDir()
	ssh := keyHome(t, home)
	keys := scanKeys(ssh, home)
	var got []string
	for _, k := range keys {
		got = append(got, k.Display+"|"+k.Type+"|"+k.Comment+"|"+map[bool]string{true: "enc", false: ""}[k.Encrypted])
	}
	want := []string{"~/.ssh/enc_key|ed25519|enc@test|enc", "~/.ssh/id_ed25519|ed25519|me@test|", "~/.ssh/id_rsa|rsa||"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("keys:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if filterKeys(keys, "me@", home)[0].Display != "~/.ssh/id_ed25519" || len(filterKeys(keys, "rsa", home)) != 1 {
		t.Fatal("filter by comment / path")
	}
	if l := filterKeys(keys, filepath.Join(ssh, "id_"), home); len(l) != 2 {
		t.Fatalf("filter by absolute path: %d", len(l))
	}
	if l := filterKeys(keys, "ide2", home); len(l) != 1 || l[0].Display != "~/.ssh/id_ed25519" {
		t.Fatal("fuzzy filter")
	}
}

func TestCheckKeyFile(t *testing.T) {
	home := t.TempDir()
	ssh := keyHome(t, home)
	os.WriteFile(filepath.Join(ssh, "open_key"), mustRead(t, filepath.Join(ssh, "id_rsa")), 0o644)
	cases := []struct {
		value string
		pp    bool
		level int
		text  string
	}{
		{"", false, checkNeutral, "ssh defaults / agent"},
		{"~/.ssh/nope", false, checkBad, "file not found"},
		{"~/.ssh/id_ed25519.pub", false, checkBad, "public key (.pub)"},
		{"~/.ssh/public_copy", false, checkBad, "public key (.pub)"},
		{"~/.ssh/notes.txt", false, checkBad, "not a private key"},
		{"~/.ssh/sub", false, checkBad, "directory"},
		{"~/.ssh/open_key", false, checkWarn, "permissions too open (chmod 600)"},
		{"~/.ssh/enc_key", false, checkWarn, "encrypted — enter the passphrase below"},
		{"~/.ssh/enc_key", true, checkOK, "valid private key (ed25519 · enc@test · passphrase)"},
		{"~/.ssh/id_ed25519", false, checkOK, "valid private key (ed25519 · me@test)"},
		{filepath.Join(ssh, "id_rsa"), false, checkOK, "valid private key (rsa)"},
	}
	for _, c := range cases {
		got := checkKeyFile(c.value, home, c.pp)
		if got.level != c.level || !strings.Contains(got.text, c.text) {
			t.Errorf("%q: got %d %q, want %d %q", c.value, got.level, got.text, c.level, c.text)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCompletePath(t *testing.T) {
	home := t.TempDir()
	ssh := keyHome(t, home)
	cases := map[string]string{
		"~":                   "/",
		"~/":                  "Documents/", // hidden entries need a dot
		"~/.s":                "sh/",
		"~/.ssh":              "/",
		"~/.ssh/":             "enc_key", // private keys first
		"~/.ssh/id_":          "ed25519",
		"~/.ssh/id_r":         "sa",
		"~/.ssh/id_ed25519.p": "ub", // .pub only when nothing else matches
		"~/.ssh/c":            "onfig",
		"~/.ssh/s":            "ub/", // directories before other files
		"~/.ssh/zzz":          "",
		"~/nope/x":            "",
		ssh + "/id_e":         "d25519",
		"":                    "",
	}
	for in, want := range cases {
		if got := completePath(in, home); got != want {
			t.Errorf("completePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// formWithKeys opens a new connection form with keys in the harness home and focuses the key file field.
func formWithKeys(t *testing.T) *harnessT {
	t.Setenv("TUSSH_SSH_DIR", "")
	h := newHarness(t, TabConnections)
	keyHome(t, h.m.opts.Home)
	h.key("n")
	h.typeIn(fName, "box")
	h.typeIn(fHost, "10.0.0.9")
	h.focusField(fKeyPath)
	return h
}

func TestKeyListPickAndEnterDoesNotSave(t *testing.T) {
	h := formWithKeys(t)
	f := h.m.form
	if len(f.keys) != 3 {
		t.Fatalf("detected %d keys", len(f.keys))
	}
	v := ansi.Strip(h.m.View())
	for _, want := range []string{"detected keys", "~/.ssh/enc_key", "~/.ssh/id_rsa", "me@test", "passphrase", "ssh defaults / agent"} {
		if !strings.Contains(v, want) {
			t.Errorf("view misses %q", want)
		}
	}
	h.key("ctrl+n", "ctrl+n", "ctrl+n", "ctrl+n") // wraps around
	if f.keySel != 0 {
		t.Fatalf("sel %d", f.keySel)
	}
	h.key("ctrl+p")
	if f.keySel != 2 {
		t.Fatalf("ctrl+p: sel %d", f.keySel)
	}
	h.key("ctrl+p", "enter")
	if h.m.form == nil || len(h.m.store.Connections) != 0 {
		t.Fatal("enter on a highlighted key must not save")
	}
	if f.focus != fKeyPath || f.inputs[fKeyPath].Value() != "~/.ssh/id_ed25519" || f.keySel != -1 {
		t.Fatalf("enter did not accept: %q focus %d", f.inputs[fKeyPath].Value(), f.focus)
	}
	if !strings.Contains(ansi.Strip(h.m.View()), "✓ valid private key (ed25519 · me@test)") {
		t.Fatal("validation hint")
	}
	// typing filters; ctrl+s saves even with a highlighted row
	h.m.form.setKeyPath("")
	h.key("rsa", "ctrl+n")
	if l := f.keyList(); len(l) != 1 || f.keySel != 0 {
		t.Fatalf("filter: %d rows, sel %d", len(l), f.keySel)
	}
	h.key("enter")
	if f.inputs[fKeyPath].Value() != "~/.ssh/id_rsa" {
		t.Fatal(f.inputs[fKeyPath].Value())
	}
	h.key("enter") // nothing highlighted: next field
	if f.focus != fPassphrase {
		t.Fatalf("focus %d", f.focus)
	}
	h.focusField(fKeyPath)
	h.key("ctrl+n", "ctrl+s")
	if h.m.form != nil {
		t.Fatalf("ctrl+s must save: %s", f.err)
	}
	if h.m.store.Connections[0].KeyPath != "~/.ssh/id_rsa" {
		t.Fatal(h.m.store.Connections[0].KeyPath)
	}
}

func TestKeyFieldGhostCompletionAndTab(t *testing.T) {
	h := formWithKeys(t)
	f := h.m.form
	h.key("~/.ssh/id_e")
	if f.ghost != "d25519" || !strings.Contains(ansi.Strip(h.m.View()), "~/.ssh/id_ed25519") {
		t.Fatalf("ghost %q", f.ghost)
	}
	h.key("right")
	if f.inputs[fKeyPath].Value() != "~/.ssh/id_ed25519" || f.ghost != "" {
		t.Fatalf("right: %q ghost %q", f.inputs[fKeyPath].Value(), f.ghost)
	}
	f.setKeyPath("")
	h.key("~/.s", "ctrl+f")
	if f.inputs[fKeyPath].Value() != "~/.ssh/" || f.ghost != "enc_key" {
		t.Fatalf("ctrl+f: %q ghost %q", f.inputs[fKeyPath].Value(), f.ghost)
	}
	// with the cursor not at the end there is no ghost, and → just moves the cursor
	h.key("left")
	if f.ghost != "" {
		t.Fatal("ghost with cursor inside the text")
	}
	h.key("right")
	if f.inputs[fKeyPath].Value() != "~/.ssh/" {
		t.Fatal("right inside the text must only move the cursor")
	}
	// no match: nothing to accept
	f.setKeyPath("")
	h.key("~/.ssh/zzz", "right")
	if f.inputs[fKeyPath].Value() != "~/.ssh/zzz" || !strings.Contains(ansi.Strip(h.m.View()), "✗ file not found") {
		t.Fatal("no match")
	}
	// Tab still moves to the next field (and never switches views)
	h.key("tab")
	if f.focus != fPassphrase || h.m.tab != TabConnections || h.m.form == nil {
		t.Fatalf("tab: focus %d", f.focus)
	}
}

func TestKeyFieldEncryptedHint(t *testing.T) {
	h := formWithKeys(t)
	f := h.m.form
	f.setKeyPath("~/.ssh/enc_key")
	if !strings.Contains(ansi.Strip(h.m.View()), "⚠ encrypted — enter the passphrase below") {
		t.Fatal("encrypted hint")
	}
	h.typeIn(fPassphrase, "s3cret")
	if !strings.Contains(ansi.Strip(h.m.View()), "✓ valid private key (ed25519 · enc@test · passphrase)") {
		t.Fatal("with passphrase")
	}
}

// TestKeyListLayout renders the form with the key list open (and scrolling) at both sizes with colors on.
func TestKeyListLayout(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	h := formWithKeys(t)
	for i := 0; i < 6; i++ {
		keygen(t, filepath.Join(h.m.form.sshDir, "extra_"+string(rune('a'+i))), "ed25519", "", "")
	}
	h.m.form.keysLoaded = false
	h.m.form.setFocus(fKeyPath)
	for _, size := range [][2]int{{110, 32}, {80, 24}} {
		h.m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		h.key("ctrl+p") // last row: the list scrolls
		v := h.m.View()
		lines := strings.Split(v, "\n")
		if len(lines) != size[1] {
			t.Fatalf("%v: %d lines", size, len(lines))
		}
		for i, l := range lines {
			if w := ansi.StringWidth(l); w > size[0] {
				t.Fatalf("%v: line %d is %d wide: %q", size, i, w, ansi.Strip(l))
			}
		}
		p := ansi.Strip(v)
		for _, want := range []string{"Key file", "detected keys 4–9 of 9", "~/.ssh/id_rsa", "ssh defaults / agent"} {
			if !strings.Contains(p, want) {
				t.Errorf("%v: misses %q:\n%s", size, want, p)
			}
		}
		h.key("esc") // clears the highlight, keeps the form
		if h.m.form == nil {
			t.Fatal("esc with a highlighted key must not close the form")
		}
	}
}

func TestConnectionsFooterHasEdit(t *testing.T) {
	h := newHarness(t, TabConnections)
	h.m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	lines := strings.Split(ansi.Strip(h.m.View()), "\n")
	foot := lines[len(lines)-1]
	if !strings.Contains(foot, "enter connect  e edit  n new  / search  ? help") || ansi.StringWidth(foot) > 80 {
		t.Fatalf("footer: %q", foot)
	}
}
