// Package agent implements what the MCP tools do: list connections visible to agents and run commands
// under the access-level policy, with approvals and the audit log.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/notify"
	"github.com/baeroe/tussh/internal/policy"
	"github.com/baeroe/tussh/internal/secrets"
	"github.com/baeroe/tussh/internal/sshrun"
)

// Service runs agent requests. Agent is the requesting harness (from MCP clientInfo), if known.
type Service struct {
	Agent string
	Queue *approval.Queue
	Poll  time.Duration
	// Notify is called for a new approval request when no TUI is open (defaults to notify.NewRequest).
	Notify func(req approval.Request)
}

// New returns a service using the default state locations.
func New(agentName string) *Service {
	return &Service{Agent: agentName, Queue: approval.Open(), Poll: 250 * time.Millisecond}
}

// ToolError is an error reported to the agent as a tool error (isError), not a protocol error.
type ToolError struct{ Msg string }

func (e *ToolError) Error() string { return e.Msg }

func toolErr(format string, a ...any) error { return &ToolError{Msg: fmt.Sprintf(format, a...)} }

// ConnectionInfo is what agents see about a connection. No hosts, users, keys or secrets.
type ConnectionInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	AccessLevel string   `json:"access_level"`
}

func loadStore() (*config.Store, error) {
	s, err := config.Load()
	if err != nil {
		// fail closed: a broken connections file exposes nothing
		return nil, toolErr("tussh config error, all connections are unavailable until it is fixed: %v", err)
	}
	return s, nil
}

// ListConnections returns connections with an access level other than none.
func (s *Service) ListConnections() ([]ConnectionInfo, error) {
	store, err := loadStore()
	if err != nil {
		return nil, err
	}
	out := []ConnectionInfo{}
	for _, c := range store.Connections {
		if c.Level() == config.LevelNone {
			continue
		}
		out = append(out, ConnectionInfo{Name: c.Name, Tags: c.Tags, Description: c.Description, AccessLevel: c.Level()})
	}
	return out, nil
}

// RunRequest is the run_command input.
type RunRequest struct {
	Connection    string
	Command       string
	Justification string
	TimeoutSec    int
}

// RunResponse is the run_command output.
type RunResponse struct {
	Connection string `json:"connection"`
	Decision   string `json:"decision"` // auto | approved
	ExitCode   *int   `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	TimedOut   bool   `json:"timed_out"`
	Truncated  bool   `json:"truncated"`
}

// RunCommand classifies, decides, waits for approval if needed, runs and audits.
func (s *Service) RunCommand(ctx context.Context, req RunRequest) (*RunResponse, error) {
	entry := audit.Entry{Connection: req.Connection, Command: req.Command, Agent: s.Agent, Justification: req.Justification}
	block := func(err error) (*RunResponse, error) {
		entry.Decision, entry.Error = audit.Blocked, err.Error()
		_ = audit.Append(entry)
		return nil, err
	}
	store, err := loadStore()
	if err != nil {
		return block(err)
	}
	conn, ok := store.ByName(req.Connection)
	if !ok || conn.Level() == config.LevelNone {
		// level none connections are invisible: same message as an unknown name
		return block(toolErr("unknown connection %q. Use list_connections to see the connections you may use.", req.Connection))
	}
	entry.AccessLevel = conn.Level()
	if strings.TrimSpace(req.Command) == "" {
		return block(toolErr("empty command"))
	}
	if len(req.Command) > classify.MaxCommandLen {
		return block(toolErr("command too long (max %d characters)", classify.MaxCommandLen))
	}
	if len(req.Justification) > 2000 {
		req.Justification = req.Justification[:2000]
		entry.Justification = req.Justification
	}

	cl := classify.LoadRules(config.RulesFile())
	res := cl.Classify(req.Command)
	dec := policy.Decide(conn.Level(), res)
	entry.Reasons = dec.Reasons

	switch dec.Outcome {
	case policy.Deny:
		return block(toolErr("connection %q: %s", conn.Name, strings.Join(dec.Reasons, "; ")))
	case policy.Approval:
		settings := config.LoadSettings()
		if e, ok := allow.Match(conn.ID, req.Command); ok {
			// "approve & remember": the user allowed exactly this command on this connection until e.Expires
			entry.Decision, entry.DecidedBy = audit.Approved, "remembered"
			entry.Reasons = append(entry.Reasons, "remembered approval until "+e.Expires.Format("2006-01-02 15:04"))
			break
		}
		timeout := settings.ApprovalTimeout()
		r := &approval.Request{
			Created: time.Now(), Expires: time.Now().Add(timeout), Connection: conn.Name, ConnectionID: conn.ID,
			Target: conn.Target(), AccessLevel: conn.Level(), Command: req.Command, Reasons: dec.Reasons,
			Agent: s.Agent, Justification: req.Justification,
		}
		if err := s.Queue.Submit(r); err != nil {
			return block(toolErr("cannot queue approval request: %v", err))
		}
		entry.RequestID = r.ID
		if !approval.TUIOpen() {
			if s.Notify != nil {
				s.Notify(*r)
			} else {
				notify.NewRequest(notify.Options{Notification: !settings.DisableNotifications, Herdr: !settings.DisableHerdr}, conn.Name, req.Command)
			}
		}
		d, err := s.Queue.Wait(r.ID, timeout, s.Poll, ctx.Done())
		if err != nil {
			return block(toolErr("approval failed: %v", err))
		}
		entry.DecidedBy = d.By
		switch d.Decision {
		case approval.Approved:
			entry.Decision = audit.Approved
		case approval.Timeout:
			entry.Decision = audit.Timeout
			_ = audit.Append(entry)
			return nil, toolErr("not approved: nobody approved the command within %s, so it was denied automatically. Reasons it needed approval: %s. Ask the user to open tussh (Alerts tab) and try again, or change your approach.", timeout, strings.Join(dec.Reasons, "; "))
		default:
			entry.Decision, entry.Note = audit.Denied, d.Note
			_ = audit.Append(entry)
			msg := "denied by the user"
			if d.Note != "" {
				msg += ": " + d.Note
			}
			return nil, toolErr("%s. Do not retry the same command; ask the user how to proceed.", msg)
		}
	default:
		entry.Decision = audit.Auto
	}

	config.TouchUsed(conn.ID)
	start := time.Now()
	out, err := sshrun.Run(ctx, conn, dec.Command, sshrun.ClampTimeout(req.TimeoutSec))
	entry.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		entry.Error = err.Error()
		_ = audit.Append(entry)
		return nil, toolErr("ssh failed: %v", err)
	}
	entry.ExitCode, entry.TimedOut = out.ExitCode, out.TimedOut
	if !config.LoadSettings().DisableAuditOutput {
		var c1, c2 bool
		redact := storedSecrets(conn)
		entry.Stdout, c1 = audit.Clip(redact(out.Stdout))
		entry.Stderr, c2 = audit.Clip(redact(out.Stderr))
		entry.OutputClipped = c1 || c2 || out.Truncated
	}
	_ = audit.Append(entry)
	decision := "auto"
	if entry.Decision == audit.Approved {
		decision = "approved"
	}
	return &RunResponse{Connection: conn.Name, Decision: decision, ExitCode: out.ExitCode, Stdout: out.Stdout,
		Stderr: out.Stderr, TimedOut: out.TimedOut, Truncated: out.Truncated}, nil
}

// storedSecrets returns a function that removes the connection's own keychain secret from text before it
// is written to the audit log (for example a password a remote program echoed back).
func storedSecrets(c config.Connection) func(string) string {
	var secret string
	kind := ""
	switch {
	case c.Auth == config.AuthPassword && c.HasPassword:
		kind = secrets.KindPassword
	case c.Auth == config.AuthKey && c.HasPassphrase:
		kind = secrets.KindPassphrase
	}
	if kind != "" {
		secret, _ = secrets.Open().Get(secrets.Account(c.ID, kind))
	}
	return func(s string) string {
		if len(secret) < 4 {
			return s
		}
		return strings.ReplaceAll(s, secret, "[redacted]")
	}
}

// IsToolError reports whether err should be returned to the agent as a tool result with isError.
func IsToolError(err error) bool {
	var te *ToolError
	return errors.As(err, &te)
}
