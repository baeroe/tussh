// Package approval is the on-disk approval queue shared by the MCP server (requester) and the TUI (resolver).
//
// Layout in <state>/approvals/:
//
//	<id>.json           the request (written atomically: temp file + rename, 0600)
//	<id>.decision.json  the decision, created exclusively (temp file + hard link), so exactly one decision wins:
//	                    a human approve/deny and the requester's timeout can race safely.
//
// The requester polls for the decision file and removes both files when done. Requests whose requester
// process is gone are cleaned up by List.
package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/baeroe/tussh/internal/config"
)

// Decisions.
const (
	Approved = "approved"
	Denied   = "denied"
	Timeout  = "timeout"
)

// Request is a pending agent command waiting for a human.
type Request struct {
	ID            string    `json:"id"`
	Created       time.Time `json:"created"`
	Expires       time.Time `json:"expires"`
	Connection    string    `json:"connection"`
	ConnectionID  string    `json:"connection_id"`
	Target        string    `json:"target,omitempty"`
	AccessLevel   string    `json:"access_level"`
	Command       string    `json:"command"`
	Reasons       []string  `json:"reasons"`
	Agent         string    `json:"agent,omitempty"`
	Justification string    `json:"justification,omitempty"`
	PID           int       `json:"pid"`
}

// Decision resolves a request.
type Decision struct {
	Decision string    `json:"decision"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	Note     string    `json:"note,omitempty"`
}

// Queue is a directory of requests.
type Queue struct{ Dir string }

// Open returns the queue in the state dir.
func Open() *Queue { return &Queue{Dir: filepath.Join(config.StateDir(), "approvals")} }

func (q *Queue) reqPath(id string) string { return filepath.Join(q.Dir, id+".json") }
func (q *Queue) decPath(id string) string { return filepath.Join(q.Dir, id+".decision.json") }

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

// Submit writes a new request. ID, Created and PID are filled in if empty.
func (q *Queue) Submit(r *Request) error {
	if r.ID == "" {
		r.ID = config.NewID()
	}
	if r.Created.IsZero() {
		r.Created = time.Now()
	}
	if r.PID == 0 {
		r.PID = os.Getpid()
	}
	if err := config.EnsureDir(q.Dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(q.reqPath(r.ID), data, 0o600)
}

// ErrAlreadyDecided means another decision won.
var ErrAlreadyDecided = errors.New("request already decided")

// ErrUnknown means the request does not exist (any more).
var ErrUnknown = errors.New("unknown or finished request")

// Resolve records a decision. Exactly one Resolve per request succeeds; later ones get ErrAlreadyDecided.
func (q *Queue) Resolve(id, decision, by, note string) error {
	if !validID(id) {
		return ErrUnknown
	}
	if decision != Approved && decision != Denied && decision != Timeout {
		return fmt.Errorf("invalid decision %q", decision)
	}
	if _, err := os.Stat(q.reqPath(id)); err != nil {
		return ErrUnknown
	}
	data, _ := json.Marshal(Decision{Decision: decision, By: by, At: time.Now(), Note: note})
	f, err := os.CreateTemp(q.Dir, ".dec-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// link(2) fails with EEXIST if a decision exists: atomic, exclusive, and the content is complete.
	if err := os.Link(tmp, q.decPath(id)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrAlreadyDecided
		}
		return err
	}
	return nil
}

// Decision reads the decision for a request, if any.
func (q *Queue) Decision(id string) (*Decision, error) {
	data, err := os.ReadFile(q.decPath(id))
	if err != nil {
		return nil, err
	}
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Wait blocks until the request is decided or timeout passes; on timeout it records a Timeout decision
// (unless a human decision won the race). poll is the polling interval. The request files are removed.
func (q *Queue) Wait(id string, timeout, poll time.Duration, cancel <-chan struct{}) (*Decision, error) {
	defer q.Remove(id)
	deadline := time.Now().Add(timeout)
	for {
		if d, err := q.Decision(id); err == nil {
			return d, nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-cancel:
			_ = q.Resolve(id, Denied, "cancelled", "the agent cancelled the request")
			if d, err := q.Decision(id); err == nil {
				return d, nil
			}
			return &Decision{Decision: Denied, By: "cancelled", At: time.Now()}, nil
		case <-time.After(poll):
		}
	}
	err := q.Resolve(id, Timeout, "timeout", fmt.Sprintf("no decision within %s", timeout))
	if err != nil && !errors.Is(err, ErrAlreadyDecided) {
		return nil, err
	}
	return q.Decision(id)
}

// Remove deletes a request and its decision.
func (q *Queue) Remove(id string) {
	if !validID(id) {
		return
	}
	_ = os.Remove(q.reqPath(id))
	_ = os.Remove(q.decPath(id))
}

// Get reads one request.
func (q *Queue) Get(id string) (*Request, error) {
	if !validID(id) {
		return nil, ErrUnknown
	}
	data, err := os.ReadFile(q.reqPath(id))
	if err != nil {
		return nil, ErrUnknown
	}
	var r Request
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Pending lists undecided requests, oldest first. Requests whose requester process is gone, or that are
// long expired, are removed.
func (q *Queue) Pending() []Request {
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		return nil
	}
	var out []Request
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".decision.json") {
			// orphaned decision (the requester finished first): clean up after a minute
			id := strings.TrimSuffix(name, ".decision.json")
			if _, err := os.Stat(q.reqPath(id)); errors.Is(err, os.ErrNotExist) {
				if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
					_ = os.Remove(filepath.Join(q.Dir, name))
				}
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !validID(id) {
			continue
		}
		if _, err := os.Stat(q.decPath(id)); err == nil {
			continue // decided, requester will clean up
		}
		r, err := q.Get(id)
		if err != nil {
			continue
		}
		if !processAlive(r.PID) || (!r.Expires.IsZero() && time.Since(r.Expires) > time.Minute) {
			q.Remove(id)
			continue
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// --- TUI presence -----------------------------------------------------------------

// PresenceDir holds one heartbeat file per running TUI.
func PresenceDir() string { return filepath.Join(config.StateDir(), "tui") }

// Heartbeat marks this TUI process as running (call periodically).
func Heartbeat() {
	dir := PresenceDir()
	if err := config.EnsureDir(dir); err != nil {
		return
	}
	p := filepath.Join(dir, fmt.Sprintf("%d", os.Getpid()))
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		_ = os.WriteFile(p, nil, 0o600)
	}
}

// ClearHeartbeat removes this process's presence file.
func ClearHeartbeat() { _ = os.Remove(filepath.Join(PresenceDir(), fmt.Sprintf("%d", os.Getpid()))) }

// TUIOpen reports whether a TUI process heartbeat is fresh.
func TUIOpen() bool {
	entries, err := os.ReadDir(PresenceDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if processAlive(pid) && time.Since(info.ModTime()) < 10*time.Second {
			return true
		}
		if !processAlive(pid) {
			_ = os.Remove(filepath.Join(PresenceDir(), e.Name()))
		}
	}
	return false
}
