// Package allow keeps "approve & remember" entries: an exact command that the user allowed on one
// connection until an expiry time. The TUI writes them, the MCP processes read them before they create an
// approval request.
//
// Layout: <state>/allow/<id>.json, one file per entry (0600, written atomically), so adding, revoking and
// reading never race on a shared file. Expired entries are removed when they are listed.
package allow

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/baeroe/tussh/internal/config"
)

// Entry allows one exact command on one connection until Expires.
type Entry struct {
	ID           string    `json:"id"`
	ConnectionID string    `json:"connection_id"`
	Connection   string    `json:"connection"`
	Command      string    `json:"command"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`
	By           string    `json:"by,omitempty"`
}

// Dir is the directory of allow entries.
func Dir() string { return filepath.Join(config.StateDir(), "allow") }

func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Add stores an entry valid for ttl. The command is matched exactly (byte for byte).
func Add(connID, connName, command string, ttl time.Duration, by string) (Entry, error) {
	if connID == "" || command == "" {
		return Entry{}, errors.New("allow: connection and command are required")
	}
	now := time.Now()
	e := Entry{ID: config.NewID(), ConnectionID: connID, Connection: connName, Command: command, Created: now,
		Expires: now.Add(ttl), By: by}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return Entry{}, err
	}
	if err := config.EnsureDir(Dir()); err != nil {
		return Entry{}, err
	}
	return e, config.WriteFileAtomic(filepath.Join(Dir(), e.ID+".json"), data, 0o600)
}

// List returns the valid entries, oldest first, and removes expired or broken ones.
func List() []Entry {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []Entry
	for _, de := range entries {
		name := de.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") || !validID(strings.TrimSuffix(name, ".json")) {
			continue
		}
		p := filepath.Join(Dir(), name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(data, &e) != nil || e.ID+".json" != name || !now.Before(e.Expires) {
			_ = os.Remove(p)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ForConnection returns the valid entries of one connection.
func ForConnection(connID string) []Entry {
	var out []Entry
	for _, e := range List() {
		if e.ConnectionID == connID {
			out = append(out, e)
		}
	}
	return out
}

// Match finds a valid entry for exactly this command on this connection.
func Match(connID, command string) (Entry, bool) {
	for _, e := range List() {
		if e.ConnectionID == connID && e.Command == command {
			return e, true
		}
	}
	return Entry{}, false
}

// Revoke removes an entry.
func Revoke(id string) error {
	if !validID(id) {
		return errors.New("allow: invalid id")
	}
	err := os.Remove(filepath.Join(Dir(), id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// RevokeConnection removes all entries of a connection (when it is deleted).
func RevokeConnection(connID string) {
	for _, e := range ForConnection(connID) {
		_ = Revoke(e.ID)
	}
}
