package sshrun

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

// fakeSSH prints its argv one per line, then behaves according to the last argument.
const fakeSSH = `#!/bin/sh
for a in "$@"; do printf 'ARG %s\n' "$a"; done
last=""
for a in "$@"; do last="$a"; done
case "$last" in
  sleep-forever) (sleep 2; echo child-survived > "$FAKE_MARK") & sleep 300 ;;
  big) i=0; while [ $i -lt 3000 ]; do echo "line $i of a long output"; i=$((i+1)); done ;;
  askpass) "$SSH_ASKPASS" "user@host's password: "; exit $? ;;
  fail) echo boom >&2; exit 3 ;;
esac
exit 0
`

func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TUSSH_CONFIG_DIR", filepath.Join(dir, "config"))
	t.Setenv("TUSSH_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("TUSSH_SSH_CONFIG", "")
	bin := filepath.Join(dir, "ssh")
	if err := os.WriteFile(bin, []byte(fakeSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUSSH_SSH_BIN", bin)
	return dir
}

func keyConn() config.Connection {
	return config.Connection{ID: "c1", Name: "web", Host: "example.com", Port: 2222, User: "deploy", Auth: config.AuthKey,
		KeyPath: "/k/id_ed25519", AccessLevel: config.LevelTrusted}
}

func has(argv []string, seq ...string) bool {
	return strings.Contains("\x00"+strings.Join(argv, "\x00")+"\x00", "\x00"+strings.Join(seq, "\x00")+"\x00")
}

func TestArgsAgentKey(t *testing.T) {
	setup(t)
	a := Args(keyConn(), ModeAgent)
	for _, want := range [][]string{
		{"-o", "BatchMode=yes"}, {"-o", "ConnectTimeout=10"}, {"-o", "ClearAllForwardings=yes"}, {"-T"},
		{"-o", "ControlPath=none"}, {"-o", "ForwardAgent=no"}, {"-p", "2222"}, {"-l", "deploy"},
		{"-i", "/k/id_ed25519", "-o", "IdentitiesOnly=yes"}, {"-o", "PreferredAuthentications=publickey"},
	} {
		if !has(a, want...) {
			t.Errorf("missing %v in %v", want, a)
		}
	}
	if a[len(a)-1] != "example.com" {
		t.Fatalf("host must be last: %v", a)
	}
}

func TestArgsPassword(t *testing.T) {
	setup(t)
	c := keyConn()
	c.Auth, c.KeyPath, c.HasPassword = config.AuthPassword, "", true
	a := Args(c, ModeAgent)
	if !has(a, "-o", "BatchMode=no") || has(a, "-o", "BatchMode=yes") || !has(a, "-o", "PubkeyAuthentication=no") {
		t.Fatalf("password args: %v", a)
	}
	if has(a, "-i") {
		t.Fatal("no -i for password auth")
	}
	ia := Args(c, ModeInteractive)
	if has(ia, "-T") || has(ia, "-o", "ClearAllForwardings=yes") || has(ia, "-o", "BatchMode=no") {
		t.Fatalf("interactive args: %v", ia)
	}
	t.Setenv("TUSSH_SSH_CONFIG", "/tmp/cfg")
	if a := Args(c, ModeAgent); a[0] != "-F" || a[1] != "/tmp/cfg" {
		t.Fatalf("-F: %v", a)
	}
}

func TestRunExitAndArgv(t *testing.T) {
	setup(t)
	r, err := Run(context.Background(), keyConn(), "fail", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode == nil || *r.ExitCode != 3 || strings.TrimSpace(r.Stderr) != "boom" || r.TimedOut {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Stdout, "ARG -T\n") || !strings.HasSuffix(r.Stdout, "ARG example.com\nARG fail\n") {
		t.Fatalf("argv: %s", r.Stdout)
	}
}

func TestRunTruncates(t *testing.T) {
	setup(t)
	r, _ := Run(context.Background(), keyConn(), "big", 10*time.Second)
	if !r.Truncated || len(r.Stdout) > MaxOutput+100 || !strings.Contains(r.Stdout, "bytes truncated") {
		t.Fatalf("truncated=%v len=%d", r.Truncated, len(r.Stdout))
	}
	if !strings.Contains(r.Stdout, "line 2999 of") {
		t.Fatal("tail missing")
	}
}

func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	dir := setup(t)
	mark := filepath.Join(dir, "mark")
	t.Setenv("FAKE_MARK", mark)
	start := time.Now()
	r, err := Run(context.Background(), keyConn(), "sleep-forever", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !r.TimedOut || r.ExitCode != nil {
		t.Fatalf("%+v", r)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("timeout not enforced")
	}
	// the background child of the fake ssh (same process group) must be killed too: it would write the mark after 2 s
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("child survived")
	}
}

func TestAskpassEndToEndViaToken(t *testing.T) {
	setup(t)
	kr := secrets.NewMem()
	c := keyConn()
	c.Auth, c.KeyPath, c.HasPassword = config.AuthPassword, "", true
	s := &config.Store{}
	s.Upsert(c)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	kr.Set(secrets.Account(c.ID, secrets.KindPassword), "pw-123")
	ap, err := NewAskpass(c, false, time.Minute)
	if err != nil || ap == nil {
		t.Fatal(err)
	}
	for _, e := range ap.Env {
		k, v, _ := strings.Cut(e, "=")
		t.Setenv(k, v)
	}
	var out bytes.Buffer
	if err := Askpass("deploy@example.com's password: ", kr, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "pw-123\n" {
		t.Fatalf("got %q", out.String())
	}
	// passphrase prompt on a password connection is refused (non-interactive)
	if err := Askpass("Enter passphrase for key: ", kr, &out); err == nil {
		t.Fatal("kind mismatch accepted")
	}
	// host key confirmation is refused non-interactively
	if err := Askpass("Are you sure you want to continue connecting (yes/no/[fingerprint])? ", kr, &out); err == nil {
		t.Fatal("host key prompt accepted")
	}
	ap.Close()
	if err := Askpass("password: ", kr, &out); err == nil {
		t.Fatal("closed token still works")
	}
	t.Setenv("TUSSH_ASKPASS_TOKEN", "../../x")
	if err := Askpass("password: ", kr, &out); err == nil {
		t.Fatal("path token accepted")
	}
}

func TestNoAskpassWithoutSecret(t *testing.T) {
	setup(t)
	if ap, _ := NewAskpass(keyConn(), false, time.Minute); ap != nil {
		t.Fatal("key without passphrase must not use askpass")
	}
}

func TestPromptKind(t *testing.T) {
	for p, want := range map[string]string{
		"root@h's password: ":                secrets.KindPassword,
		"Password:":                          secrets.KindPassword,
		"Enter passphrase for key '/k/id': ": secrets.KindPassphrase,
		"Are you sure you want to continue connecting (yes/no)? ": "confirm",
		"Verification code: ": "other",
	} {
		if got := PromptKind(p); got != want {
			t.Errorf("%q: %s want %s", p, got, want)
		}
	}
}

func TestClampTimeout(t *testing.T) {
	if ClampTimeout(0) != DefaultTimeout || ClampTimeout(9999) != MaxTimeout || ClampTimeout(5) != 5*time.Second {
		t.Fatal("clamp")
	}
}
