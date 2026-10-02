package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func valid() Connection {
	return Connection{Name: "web", Host: "example.com", User: "deploy", Auth: AuthKey, AccessLevel: LevelReadOnly}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(c *Connection){
		func(c *Connection) { c.Name = "" },
		func(c *Connection) { c.Name = "-x" },
		func(c *Connection) { c.Name = "a b" },
		func(c *Connection) { c.Host = "-oProxyCommand=evil" },
		func(c *Connection) { c.Host = "a b" },
		func(c *Connection) { c.Host = "" },
		func(c *Connection) { c.User = "-l" },
		func(c *Connection) { c.Port = 70000 },
		func(c *Connection) { c.Auth = "kerberos" },
		func(c *Connection) { c.AccessLevel = "root" },
		func(c *Connection) { c.KeyPath = "-i" },
		func(c *Connection) { c.Tunnels = []Tunnel{{Name: "x", Local: 0, RemoteHost: "a", RemotePort: 1}} },
		func(c *Connection) { c.Tunnels = []Tunnel{{Name: "x", Local: 1, RemoteHost: "a -oX", RemotePort: 1}} },
		func(c *Connection) {
			c.Tunnels = []Tunnel{{Name: "x", Local: 1, RemoteHost: "a", RemotePort: 1}, {Name: "x", Local: 2, RemoteHost: "a", RemotePort: 1}}
		},
	}
	for i, f := range bad {
		c := valid()
		f(&c)
		if c.Validate() == nil {
			t.Errorf("case %d: %+v should be invalid", i, c)
		}
	}
}

func TestLevelFailsClosed(t *testing.T) {
	c := valid()
	c.AccessLevel = "admin"
	if c.Level() != LevelNone {
		t.Fatal("unknown level must be none")
	}
}

func TestStoreRoundTripNoSecrets(t *testing.T) {
	t.Setenv("TUSSH_CONFIG_DIR", t.TempDir())
	s, err := Load()
	if err != nil || len(s.Connections) != 0 {
		t.Fatalf("empty store: %v", err)
	}
	c := valid()
	c.HasPassword = true
	c.Tunnels = []Tunnel{{Name: "db", Local: 3307, RemoteHost: "127.0.0.1", RemotePort: 3306}}
	c, err = s.Upsert(c)
	if err != nil || c.ID == "" {
		t.Fatal(err)
	}
	if _, err := s.Upsert(Connection{Name: "web", Host: "x", Auth: AuthKey, AccessLevel: LevelNone}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(ConnectionsFile())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	data, _ := os.ReadFile(ConnectionsFile())
	if strings.Contains(strings.ToLower(string(data)), `"password"`) && !strings.Contains(string(data), `"auth": "password"`) {
		t.Fatal("a password field leaked into connections.json")
	}
	s2, err := Load()
	if err != nil || len(s2.Connections) != 1 || s2.Connections[0].Tunnels[0].Spec() != "127.0.0.1:3307:127.0.0.1:3306" {
		t.Fatalf("reload: %+v %v", s2, err)
	}
	if !s2.Delete(c.ID) || len(s2.Connections) != 0 {
		t.Fatal("delete")
	}
}

func TestInvalidStoreIsError(t *testing.T) {
	t.Setenv("TUSSH_CONFIG_DIR", t.TempDir())
	os.WriteFile(ConnectionsFile(), []byte("{nope"), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("invalid JSON must be an error")
	}
}

func TestDirsAndSettings(t *testing.T) {
	t.Setenv("TUSSH_CONFIG_DIR", "/c")
	t.Setenv("TUSSH_STATE_DIR", "/s")
	if ConfigDir() != "/c" || StateDir() != "/s" {
		t.Fatal("env overrides")
	}
	t.Setenv("TUSSH_CONFIG_DIR", t.TempDir())
	if LoadSettings().ApprovalTimeout() != 120*time.Second {
		t.Fatal("default timeout")
	}
	os.WriteFile(SettingsFile(), []byte(`{"approval_timeout_seconds": 30}`), 0o600)
	if LoadSettings().ApprovalTimeout() != 30*time.Second {
		t.Fatal("settings timeout")
	}
	t.Setenv("TUSSH_APPROVAL_TIMEOUT", "2")
	if LoadSettings().ApprovalTimeout() != 2*time.Second {
		t.Fatal("env timeout")
	}
}

func TestLegacyGroupBecomesTag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TUSSH_CONFIG_DIR", dir)
	legacy := `{"version": 1, "connections": [
  {"id": "a1", "name": "web", "group": "lulububu", "host": "web.example", "auth": "key", "access_level": "read-only"},
  {"id": "b2", "name": "db", "group": "Prod", "tags": ["prod", "mysql"], "host": "db.example", "auth": "key", "access_level": "none"},
  {"id": "c3", "name": "plain", "host": "p.example", "auth": "key", "access_level": "none", "favorite": true}
]}`
	os.WriteFile(ConnectionsFile(), []byte(legacy), 0o600)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	web, _ := s.ByName("web")
	db, _ := s.ByName("db")
	plain, _ := s.ByName("plain")
	if strings.Join(web.Tags, ",") != "lulububu" || strings.Join(db.Tags, ",") != "Prod,mysql" || len(plain.Tags) != 0 || !plain.Favorite {
		t.Fatalf("migration: %v %v %v", web.Tags, db.Tags, plain.Tags)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(ConnectionsFile())
	if strings.Contains(string(data), `"group"`) || !strings.Contains(string(data), `"lulububu"`) {
		t.Fatalf("saved: %s", data)
	}
}

func TestTags(t *testing.T) {
	if got := strings.Join(ParseTags(" prod, shop ,, PROD,  two  words "), "|"); got != "prod|shop|two words" {
		t.Fatal(got)
	}
	c := valid()
	c.Tags = []string{"ok", "a,b"}
	if c.Validate() == nil {
		t.Fatal("comma in tag accepted")
	}
	c.Tags = []string{strings.Repeat("x", 33)}
	if c.Validate() == nil {
		t.Fatal("long tag accepted")
	}
	if !(Connection{Tags: []string{"Prod"}}).HasTag("prod") {
		t.Fatal("HasTag")
	}
}

func TestLastUsed(t *testing.T) {
	t.Setenv("TUSSH_STATE_DIR", t.TempDir())
	if len(LastUsed()) != 0 {
		t.Fatal("not empty")
	}
	TouchUsed("abc")
	TouchUsed("../evil")
	u := LastUsed()
	if len(u) != 1 || time.Since(u["abc"]) > time.Minute {
		t.Fatalf("%v", u)
	}
	ForgetUsed("abc")
	if len(LastUsed()) != 0 {
		t.Fatal("not forgotten")
	}
}

func TestRememberTTL(t *testing.T) {
	if (Settings{}).RememberTTL() != 8*time.Hour || (Settings{RememberTTLHours: 2}).RememberTTL() != 2*time.Hour ||
		(Settings{RememberTTLHours: 1000}).RememberTTL() != 168*time.Hour {
		t.Fatal("ttl")
	}
}
