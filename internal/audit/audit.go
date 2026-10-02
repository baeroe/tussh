// Package audit appends one JSON line per agent request to <state>/audit.jsonl (0600).
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/baeroe/tussh/internal/config"
)

// Decisions recorded in the log.
const (
	Auto     = "auto"
	Approved = "approved"
	Denied   = "denied"
	Timeout  = "timeout"
	Blocked  = "blocked" // policy deny (level none, unknown connection, invalid input)
)

// Entry is one audit record. Command output is not logged.
type Entry struct {
	Time          time.Time `json:"time"`
	Connection    string    `json:"connection"`
	AccessLevel   string    `json:"access_level,omitempty"`
	Command       string    `json:"command"`
	Decision      string    `json:"decision"`
	DecidedBy     string    `json:"decided_by,omitempty"`
	Reasons       []string  `json:"reasons,omitempty"`
	Agent         string    `json:"agent,omitempty"`
	Justification string    `json:"justification,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	ExitCode      *int      `json:"exit_code,omitempty"`
	TimedOut      bool      `json:"timed_out,omitempty"`
	Error         string    `json:"error,omitempty"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
}

// File is the audit log path.
func File() string { return filepath.Join(config.StateDir(), "audit.jsonl") }

// Append writes an entry (one write call with O_APPEND, so concurrent writers do not interleave lines).
func Append(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := config.EnsureDir(config.StateDir()); err != nil {
		return err
	}
	f, err := os.OpenFile(File(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// Read returns the newest entries first, at most limit (0 = all). Broken lines are skipped.
func Read(limit int) ([]Entry, error) {
	f, err := os.Open(File())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	out := make([]Entry, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		out = append(out, all[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, sc.Err()
}
