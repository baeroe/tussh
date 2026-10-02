// Package secrets stores connection passwords and key passphrases outside the connection file.
//
// Default backend: the OS keyring via github.com/zalando/go-keyring (macOS Keychain, Secret Service on Linux),
// service name "tussh". TUSSH_KEYRING=file:<path> selects a plaintext JSON file backend for tests only.
package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

// Service is the keyring service name.
const Service = "tussh"

// Kinds of secrets per connection.
const (
	KindPassword   = "password"
	KindPassphrase = "passphrase"
)

// ErrNotFound means no secret is stored.
var ErrNotFound = errors.New("secret not found")

// Keyring is the minimal secret store interface.
type Keyring interface {
	Get(account string) (string, error)
	Set(account, secret string) error
	Delete(account string) error
}

// Account is the keyring account for a connection secret: "<connection id>:<kind>".
func Account(connID, kind string) string { return connID + ":" + kind }

// Open returns the configured keyring.
func Open() Keyring {
	if v := os.Getenv("TUSSH_KEYRING"); strings.HasPrefix(v, "file:") {
		return &FileKeyring{Path: strings.TrimPrefix(v, "file:")}
	}
	return systemKeyring{}
}

// Describe names the active backend for the UI.
func Describe() string {
	if v := os.Getenv("TUSSH_KEYRING"); strings.HasPrefix(v, "file:") {
		return "file " + strings.TrimPrefix(v, "file:") + " (TESTING ONLY, plaintext)"
	}
	return "system keyring (macOS Keychain / Secret Service), service \"" + Service + "\""
}

type systemKeyring struct{}

func (systemKeyring) Get(account string) (string, error) {
	s, err := keyring.Get(Service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return s, err
}

func (systemKeyring) Set(account, secret string) error { return keyring.Set(Service, account, secret) }

func (systemKeyring) Delete(account string) error {
	err := keyring.Delete(Service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// MemKeyring is an in-memory keyring for tests.
type MemKeyring struct {
	mu sync.Mutex
	m  map[string]string
}

// NewMem returns an empty in-memory keyring.
func NewMem() *MemKeyring { return &MemKeyring{m: map[string]string{}} }

func (k *MemKeyring) Get(account string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.m[account]
	if !ok {
		return "", ErrNotFound
	}
	return s, nil
}

func (k *MemKeyring) Set(account, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[account] = secret
	return nil
}

func (k *MemKeyring) Delete(account string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, account)
	return nil
}

// FileKeyring is a plaintext JSON file (0600). Only for tests that span processes.
type FileKeyring struct {
	Path string
	mu   sync.Mutex
}

func (k *FileKeyring) load() (map[string]string, error) {
	m := map[string]string{}
	data, err := os.ReadFile(k.Path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (k *FileKeyring) save(m map[string]string) error {
	data, _ := json.Marshal(m)
	if err := os.MkdirAll(filepath.Dir(k.Path), 0o700); err != nil {
		return err
	}
	tmp := k.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, k.Path)
}

func (k *FileKeyring) Get(account string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.load()
	if err != nil {
		return "", err
	}
	s, ok := m[account]
	if !ok {
		return "", ErrNotFound
	}
	return s, nil
}

func (k *FileKeyring) Set(account, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.load()
	if err != nil {
		return err
	}
	m[account] = secret
	return k.save(m)
}

func (k *FileKeyring) Delete(account string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.load()
	if err != nil {
		return err
	}
	delete(m, account)
	return k.save(m)
}
