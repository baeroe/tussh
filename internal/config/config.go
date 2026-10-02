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
	"strconv"
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
//
// Older files had a "group" field; it is read as a tag (see UnmarshalJSON) and dropped on the next save.
type Connection struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Favorite    bool     `json:"favorite,omitempty"`
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
	// CreatedBy is "agent" for connections an agent created with the MCP tool new_connection;
	// CreatedAgent is the harness (MCP clientInfo name and version), if known.
	CreatedBy    string    `json:"created_by,omitempty"`
	CreatedAgent string    `json:"created_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitzero"`
	// NeedsSetup is set on agent-created connections until the user saved them in the form.
	NeedsSetup bool `json:"needs_setup,omitempty"`
}

// CreatedByAgent is the CreatedBy value of connections made by the new_connection tool.
const CreatedByAgent = "agent"

// UnmarshalJSON reads a connection and migrates the legacy "group" field into a tag.
func (c *Connection) UnmarshalJSON(data []byte) error {
	type plain Connection // no methods: avoids recursion
	var aux struct {
		plain
		Group string `json:"group"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*c = Connection(aux.plain)
	if g := strings.TrimSpace(aux.Group); g != "" {
		c.Tags = NormalizeTags(append([]string{g}, c.Tags...))
	}
	return nil
}

// NormalizeTags trims tags, drops empty ones and case-insensitive duplicates (first spelling wins).
func NormalizeTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.Join(strings.Fields(t), " ")
		k := strings.ToLower(t)
		if t == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, t)
	}
	return out
}

// ParseTags splits a comma-separated tag list.
func ParseTags(s string) []string { return NormalizeTags(strings.Split(s, ",")) }

// HasTag reports whether the connection has the tag (case-insensitive).
func (c Connection) HasTag(tag string) bool {
	for _, t := range c.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
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
	for _, t := range c.Tags {
		if len(t) > 32 || strings.ContainsAny(t, ",\n\r\x00") || strings.TrimSpace(t) != t || t == "" {
			return fmt.Errorf("tag %q: 1-32 characters, no commas", t)
		}
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

// FormatTunnels renders tunnels as "name=[bind:]local:host:port, ...".
func FormatTunnels(ts []Tunnel) string {
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

// ParseTunnels parses "name=[bind:]local:host:port, ..." (the syntax of the form and of new_connection).
// The tunnels are not validated here; Connection.Validate does that.
func ParseTunnels(s string) ([]Tunnel, error) {
	var out []Tunnel
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
		var t Tunnel
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

// Save writes connections.json atomically with mode 0600. It overwrites the file with this store; writers
// that may race with another process (the TUI and the MCP tool new_connection) use Update instead.
func (s *Store) Save() error { return s.SaveFile(ConnectionsFile()) }

// Update is the read-modify-write for connections.json: under an exclusive lock on connections.json.lock it
// loads the current file, applies fn and saves the result atomically (when fn returns no error). The TUI and
// the MCP processes both write through Update, so no process overwrites an entry another one just added.
// An invalid file is never overwritten.
func Update(fn func(*Store) error) (*Store, error) {
	path := ConnectionsFile()
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", filepath.Base(path), err)
	}
	defer unlock()
	s, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	if err := fn(s); err != nil {
		return nil, err
	}
	if err := s.SaveFile(path); err != nil {
		return nil, err
	}
	return s, nil
}

// FileStamp identifies the current version of connections.json (zero if missing); the TUI reloads when
// it changes.
func FileStamp() string {
	st, err := os.Stat(ConnectionsFile())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d/%d", st.ModTime().UnixNano(), st.Size())
}

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

// Sort orders by name (the TUI applies its own order: favorites, last used, name).
func (s *Store) Sort() {
	sort.SliceStable(s.Connections, func(i, j int) bool {
		return strings.ToLower(s.Connections[i].Name) < strings.ToLower(s.Connections[j].Name)
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
	// RememberTTLHours is how long "approve & remember" allows a command (default 8, max 168).
	RememberTTLHours int `json:"remember_ttl_hours,omitempty"`
	// DisableAuditOutput stops tussh from keeping the (bounded) command output in the audit log.
	DisableAuditOutput bool `json:"disable_audit_output,omitempty"`
}

// DefaultRememberTTL is how long a remembered approval is valid.
const DefaultRememberTTL = 8 * time.Hour

// RememberTTL returns the configured TTL for remembered approvals.
func (s Settings) RememberTTL() time.Duration {
	switch {
	case s.RememberTTLHours <= 0:
		return DefaultRememberTTL
	case s.RememberTTLHours > 168:
		return 168 * time.Hour
	}
	return time.Duration(s.RememberTTLHours) * time.Hour
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

// --- Last used -----------------------------------------------------------------

// The last use of a connection (interactive session or agent command) is kept in the state dir, one empty
// file per connection id whose mtime is the time of use, so agent runs never rewrite connections.json.

func usedDir() string { return filepath.Join(StateDir(), "used") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// TouchUsed records that connection id was used now.
func TouchUsed(id string) {
	if !idRE.MatchString(id) {
		return
	}
	if err := EnsureDir(usedDir()); err != nil {
		return
	}
	p := filepath.Join(usedDir(), id)
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		_ = os.WriteFile(p, nil, 0o600)
	}
}

// LastUsed returns the last use per connection id.
func LastUsed() map[string]time.Time {
	out := map[string]time.Time{}
	entries, err := os.ReadDir(usedDir())
	if err != nil {
		return out
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && idRE.MatchString(e.Name()) {
			out[e.Name()] = info.ModTime()
		}
	}
	return out
}

// ForgetUsed removes the record for a deleted connection.
func ForgetUsed(id string) {
	if idRE.MatchString(id) {
		_ = os.Remove(filepath.Join(usedDir(), id))
	}
}
