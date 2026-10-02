package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func exercise(t *testing.T, k Keyring) {
	t.Helper()
	if _, err := k.Get("a:password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if err := k.Set("a:password", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if s, err := k.Get("a:password"); err != nil || s != "s3cret" {
		t.Fatalf("get: %q %v", s, err)
	}
	if err := k.Delete("a:password"); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete("a:password"); err != nil {
		t.Fatal("deleting a missing secret must not fail")
	}
	if _, err := k.Get("a:password"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted secret still there")
	}
}

func TestMemKeyring(t *testing.T) { exercise(t, NewMem()) }

func TestFileKeyring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.json")
	t.Setenv("TUSSH_KEYRING", "file:"+path)
	k := Open()
	if _, ok := k.(*FileKeyring); !ok {
		t.Fatalf("Open returned %T", k)
	}
	exercise(t, k)
	k.Set("x", "y")
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestAccount(t *testing.T) {
	if Account("abc", KindPassphrase) != "abc:passphrase" {
		t.Fatal(Account("abc", KindPassphrase))
	}
}
