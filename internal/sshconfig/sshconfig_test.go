package sshconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// Ported from herdr-ssh SshConfigTests.
const cfg = `
# comment
Host *
    ServerAliveInterval 30

Host web1 web2
    HostName 10.0.0.1
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_web

Host db-* !bad
    User root

Host "spaced alias"

Host plain
HostName=plain.example.com

Match host foo
    User matched

Include conf.d/*.conf
Include ~/nonexistent-tussh-test/*
Host web1
    User ignored-second-value
`

func TestParse(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0o600)
	os.MkdirAll(filepath.Join(dir, "conf.d"), 0o700)
	os.WriteFile(filepath.Join(dir, "conf.d", "b.conf"), []byte("Host inc-b\n  HostName b.example.com\nInclude ../nested.cfg\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "conf.d", "a.conf"), []byte("Host inc-a\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "nested.cfg"), []byte("Host nested ?wild\nInclude nested.cfg\n"), 0o600)
	hosts := Parse(filepath.Join(dir, "config"))
	var aliases []string
	byAlias := map[string]Host{}
	for _, h := range hosts {
		aliases = append(aliases, h.Alias)
		byAlias[h.Alias] = h
	}
	want := []string{"web1", "web2", "plain", "inc-a", "inc-b", "nested"}
	if len(aliases) != len(want) {
		t.Fatalf("aliases %v", aliases)
	}
	for i := range want {
		if aliases[i] != want[i] {
			t.Fatalf("aliases %v", aliases)
		}
	}
	w := byAlias["web1"]
	if w.HostName != "10.0.0.1" || w.User != "deploy" || w.Port != 2222 || w.IdentityFile != "~/.ssh/id_web" {
		t.Fatalf("web1 %+v", w)
	}
	if byAlias["plain"].HostName != "plain.example.com" || byAlias["inc-b"].HostName != "b.example.com" {
		t.Fatal("fields")
	}
	if len(Parse(filepath.Join(dir, "missing"))) != 0 {
		t.Fatal("missing file")
	}
}
