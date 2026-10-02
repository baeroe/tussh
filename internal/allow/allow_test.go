package allow

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAddMatchExpireRevoke(t *testing.T) {
	t.Setenv("TUSSH_STATE_DIR", t.TempDir())
	e, err := Add("c1", "web", "systemctl restart nginx", time.Hour, "tui")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Match("c1", "systemctl restart nginx"); !ok {
		t.Fatal("exact command must match")
	}
	for _, c := range []struct{ conn, cmd string }{{"c2", "systemctl restart nginx"}, {"c1", "systemctl restart nginx "},
		{"c1", "systemctl restart nginx; rm -rf /"}, {"c1", "systemctl restart"}} {
		if _, ok := Match(c.conn, c.cmd); ok {
			t.Errorf("%q on %s must not match", c.cmd, c.conn)
		}
	}
	info, _ := os.Stat(filepath.Join(Dir(), e.ID+".json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	if _, err := Add("c1", "web", "reboot", -time.Second, "tui"); err != nil {
		t.Fatal(err)
	}
	if _, ok := Match("c1", "reboot"); ok {
		t.Fatal("expired entry matched")
	}
	if n := len(List()); n != 1 {
		t.Fatalf("list: %d", n)
	}
	if err := Revoke(e.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := Match("c1", "systemctl restart nginx"); ok {
		t.Fatal("revoked entry matched")
	}
	if Revoke("../x") == nil {
		t.Fatal("invalid id accepted")
	}
}
