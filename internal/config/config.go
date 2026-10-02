// Package config holds the connection store (connections.json), settings and the file locations of tussh.
//
// The store never contains secrets: passwords and key passphrases live in the keyring (see package secrets).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Access levels for agents.
const (
	LevelNone        = "none"
	LevelReadOnly    = "read-only"
	LevelApproveEach = "approve-each"
	LevelTrusted     = "trusted"
)

// Levels in the order the TUI cycles through them.
var Levels = []string{LevelNone, LevelReadOnly, LevelApproveEach, LevelTrusted}

// Auth methods.
const (
	AuthKey      = "key"
	AuthPassword = "password"
)

// ValidLevel reports whether s is a known access level.
func ValidLevel(s string) bool {
	for _, l := range Levels {
		if l == s {
			return true
		}
	}
	return false
}

// --- Paths -------------------------------------------------------------------

// ConfigDir is $TUSSH_CONFIG_DIR, else $XDG_CONFIG_HOME/tussh, else ~/.config/tussh.
// (~/.config on macOS too: a terminal tool, and easier to find than ~/Library/Application Support.)
func ConfigDir() string {
	if d := os.Getenv("TUSSH_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "tussh")
	}
	return filepath.Join(home(), ".config", "tussh")
}

// StateDir is $TUSSH_STATE_DIR, else $XDG_STATE_HOME/tussh, else ~/.local/state/tussh.
func StateDir() string {
	if d := os.Getenv("TUSSH_STATE_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "tussh")
	}
	return filepath.Join(home(), ".local", "state", "tussh")
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "."
	}
	return h
}

// ConnectionsFile is the connection store.
func ConnectionsFile() string { return filepath.Join(ConfigDir(), "connections.json") }

// RulesFile holds user-defined sensitive command rules.
func RulesFile() string { return filepath.Join(ConfigDir(), "rules.json") }

// SettingsFile holds optional settings.
func SettingsFile() string { return filepath.Join(ConfigDir(), "settings.json") }

// EnsureDir creates dir with 0700.
func EnsureDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// WriteFileAtomic writes data to path via a temp file + rename, with the given mode.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// --- Connections ---------------------------------------------------------------

// Tunnel is a local port forward: bind:local -> remote_host:remote_port (ssh -L).
type Tunnel struct {
	Name       string `json:"name"`
	Local      int    `json:"local"`
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
	Bind       string `json:"bind,omitempty"`
}

// BindAddr defaults to 127.0.0.1.
func (t Tunnel) BindAddr() string {
	if t.Bind == "" {
		return "127.0.0.1"
	}
	return t.Bind
}

// Spec is the ssh -L argument.
func (t Tunnel) Spec() string {
	return fmt.Sprintf("%s:%d:%s:%d", t.BindAddr(), t.Local, t.RemoteHost, t.RemotePort)
}

// Connection is one SSH target. Secrets are not stored here.
type Connection struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Group       string   `json:"group,omitempty"`
	Description string   `json:"description,omitempty"`
	Host        string   `json:"host"`
	Port        int      `json:"port,omitempty"`
	User        string   `json:"user,omitempty"`
	Auth        string   `json:"auth"`               // key | password
	KeyPath     string   `json:"key_path,omitempty"` // auth key; empty = ssh defaults / agent
	AccessLevel string   `json:"access_level"`
	Tunnels     []Tunnel `json:"tunnels,omitempty"`
	// HasPassword / HasPassphrase record whether a secret was stored in the keyring (not the secret itself).
	HasPassword   bool `json:"has_password,omitempty"`
	HasPassphrase bool `json:"has_passphrase,omitempty"`
}

// EffectivePort defaults to 22.
func (c Connection) EffectivePort() int {
	if c.Port == 0 {
		return 22
	}
	return c.Port
}

// Level returns the access level; anything unknown counts as none (fail closed).
func (c Connection) Level() string {
	if ValidLevel(c.AccessLevel) {
		return c.AccessLevel
	}
	return LevelNone
}

// Target is user@host:port for display.
func (c Connection) Target() string {
	s := c.Host
	if c.User != "" {
		s = c.User + "@" + s
	}
	if c.EffectivePort() != 22 {
		s += fmt.Sprintf(":%d", c.EffectivePort())
	}
	return s
}

var (
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$`)
	hostRE   = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]%-]+$`)
	userRE   = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.@-]*$`)
	tunnelRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	rhostRE  = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]+$`)
)

// Validate checks a connection. Values end up in an ssh argv, so nothing may start with "-".
func (c Connection) Validate() error {
	if !nameRE.MatchString(c.Name) {
		return errors.New("name: 1-64 characters, letters, digits, _ . @ - (must start with a letter or digit)")
	}
	if c.Host == "" || strings.HasPrefix(c.Host, "-") || !hostRE.MatchString(c.Host) {
		return errors.New("host: invalid hostname or address")
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("port: must be 1-65535")
	}
	if c.User != "" && !userRE.MatchString(c.User) {
		return errors.New("user: invalid user name")
	}
	if c.Auth != AuthKey && c.Auth != AuthPassword {
		return errors.New("auth: must be key or password")
	}
	if strings.HasPrefix(c.KeyPath, "-") || strings.ContainsAny(c.KeyPath, "\n\r\x00") {
		return errors.New("key path: invalid")
	}
	if !ValidLevel(c.AccessLevel) {
		return fmt.Errorf("access level: must be one of %s", strings.Join(Levels, ", "))
	}
	seen := map[string]bool{}
	for _, t := range c.Tunnels {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
		if seen[t.Name] {
			return fmt.Errorf("tunnel %q: duplicate name", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

// Validate checks a tunnel definition.
func (t Tunnel) Validate() error {
	if !tunnelRE.MatchString(t.Name) {
		return errors.New("name: letters, digits, _ . -")
	}
	if t.Local < 1 || t.Local > 65535 || t.RemotePort < 1 || t.RemotePort > 65535 {
		return errors.New("ports must be 1-65535")
	}
	if !rhostRE.MatchString(t.RemoteHost) || strings.HasPrefix(t.RemoteHost, "-") {
		return errors.New("remote host: invalid")
	}
	if t.Bind != "" && (!rhostRE.MatchString(t.Bind) || strings.HasPrefix(t.Bind, "-")) {
		return errors.New("bind: invalid")
	}
	return nil
}

// KeyPathExpanded resolves a leading ~/.
func (c Connection) KeyPathExpanded() string {
	if strings.HasPrefix(c.KeyPath, "~/") {
		return filepath.Join(home(), c.KeyPath[2:])
	}
	return c.KeyPath
}

// Store is the on-disk connection list.
type Store struct {
	Version     int          `json:"version"`
	Connections []Connection `json:"connections"`
}

// Load reads connections.json. A missing file is an empty store. An invalid file is an error;
// callers must fail closed (the MCP server then exposes nothing).
func Load() (*Store, error) {
	return LoadFile(ConnectionsFile())
}

// LoadFile reads a store from path.
func LoadFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Store{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	return &s, nil
}

// Save writes connections.json atomically with mode 0600.
func (s *Store) Save() error { return s.SaveFile(ConnectionsFile()) }

// SaveFile writes the store to path.
func (s *Store) SaveFile(path string) error {
	s.Version = 1
	s.Sort()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(data, '\n'), 0o600)
}

// Sort orders by group, then name.
func (s *Store) Sort() {
	sort.SliceStable(s.Connections, func(i, j int) bool {
		a, b := s.Connections[i], s.Connections[j]
		if a.Group != b.Group {
			if a.Group == "" {
				return false
			}
			if b.Group == "" {
				return true
			}
			return strings.ToLower(a.Group) < strings.ToLower(b.Group)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}

// ByName finds a connection by its (unique) name.
func (s *Store) ByName(name string) (Connection, bool) {
	for _, c := range s.Connections {
		if c.Name == name {
			return c, true
		}
	}
	return Connection{}, false
}

// ByID finds a connection by id.
func (s *Store) ByID(id string) (Connection, bool) {
	for _, c := range s.Connections {
		if c.ID == id {
			return c, true
		}
	}
	return Connection{}, false
}

// Upsert validates and inserts or replaces (by ID) a connection. Names must be unique.
func (s *Store) Upsert(c Connection) (Connection, error) {
	if c.ID == "" {
		c.ID = NewID()
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	for _, o := range s.Connections {
		if o.Name == c.Name && o.ID != c.ID {
			return c, fmt.Errorf("name: %q is already used", c.Name)
		}
	}
	for i, o := range s.Connections {
		if o.ID == c.ID {
			s.Connections[i] = c
			s.Sort()
			return c, nil
		}
	}
	s.Connections = append(s.Connections, c)
	s.Sort()
	return c, nil
}

// Delete removes a connection by id.
func (s *Store) Delete(id string) bool {
	for i, o := range s.Connections {
		if o.ID == id {
			s.Connections = append(s.Connections[:i], s.Connections[i+1:]...)
			return true
		}
	}
	return false
}

// NewID returns a random hex id.
func NewID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// --- Settings ------------------------------------------------------------------

// Settings are optional knobs in settings.json.
type Settings struct {
	ApprovalTimeoutSeconds int  `json:"approval_timeout_seconds,omitempty"`
	DisableNotifications   bool `json:"disable_notifications,omitempty"`
	DisableHerdr           bool `json:"disable_herdr,omitempty"`
}

// DefaultApprovalTimeout is how long an agent call waits for a decision.
const DefaultApprovalTimeout = 120 * time.Second

// LoadSettings reads settings.json (missing or invalid = defaults). Env overrides:
// TUSSH_APPROVAL_TIMEOUT (seconds), TUSSH_NO_NOTIFY=1.
func LoadSettings() Settings {
	var s Settings
	if data, err := os.ReadFile(SettingsFile()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if v := os.Getenv("TUSSH_APPROVAL_TIMEOUT"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			s.ApprovalTimeoutSeconds = n
		}
	}
	if os.Getenv("TUSSH_NO_NOTIFY") == "1" {
		s.DisableNotifications = true
		s.DisableHerdr = true
	}
	return s
}

// ApprovalTimeout returns the configured timeout (default 120 s, max 1 h).
func (s Settings) ApprovalTimeout() time.Duration {
	if s.ApprovalTimeoutSeconds <= 0 {
		return DefaultApprovalTimeout
	}
	if s.ApprovalTimeoutSeconds > 3600 {
		return time.Hour
	}
	return time.Duration(s.ApprovalTimeoutSeconds) * time.Second
}
