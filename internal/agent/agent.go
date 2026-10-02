// Package agent implements what the MCP tools do: list connections visible to agents and run commands
// under the access-level policy, with approvals and the audit log.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
	// NotifyNewConn is called for a connection created with new_connection when no TUI is open
	// (defaults to notify.NewConnection).
	NotifyNewConn func(agent, connection string)
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

// --- new_connection ------------------------------------------------------------------------

// NewConnArgs are the fields an agent may set with new_connection. Access level, auth method, key file and
// secrets are deliberately missing: only the user sets them, in tussh.
type NewConnArgs struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port,omitempty"`
	User        string   `json:"user,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Tunnels     []string `json:"tunnels,omitempty"`
}

// NewConnResponse is the new_connection result.
type NewConnResponse struct {
	Connection  string `json:"connection"`
	Created     bool   `json:"created"`
	Usable      bool   `json:"usable"`
	AccessLevel string `json:"access_level"`
	NeedsSetup  bool   `json:"needs_setup"`
	Message     string `json:"message"`
}

// MaxPendingSetup limits how many agent-created connections may wait for the user's setup at once.
const MaxPendingSetup = 20

// forbiddenNewConnFields are fields agents might try to send; they get a specific error (and their values
// are never logged, they may be secrets).
var forbiddenNewConnFields = map[string]string{
	"access_level": "the access level", "level": "the access level", "accesslevel": "the access level",
	"auth": "the authentication method", "auth_method": "the authentication method", "method": "the authentication method",
	"key": "the key file", "key_path": "the key file", "keyfile": "the key file", "key_file": "the key file",
	"identity_file": "the key file", "identityfile": "the key file",
	"password": "the password", "passphrase": "the key passphrase", "secret": "secrets",
	"has_password": "secrets", "has_passphrase": "secrets",
	"id": "internal fields", "created_by": "internal fields", "created_agent": "internal fields",
	"created_at": "internal fields", "needs_setup": "internal fields", "favorite": "internal fields",
}

// NewConnection creates a connection from an agent's arguments (raw JSON, decoded strictly). The connection
// gets access level none, no credentials and needs_setup, so it stays invisible to agents until the user
// sets it up in tussh. Every call is audited.
func (s *Service) NewConnection(raw json.RawMessage) (*NewConnResponse, error) {
	entry := audit.Entry{Command: "new_connection", Agent: s.Agent, AccessLevel: config.LevelNone}
	reject := func(err error) (*NewConnResponse, error) {
		entry.Decision, entry.Error = audit.Blocked, err.Error()
		_ = audit.Append(entry)
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return reject(toolErr("invalid arguments: expected a JSON object"))
	}
	var names, forbidden, unknown []string
	allowed := map[string]bool{"name": true, "host": true, "port": true, "user": true, "description": true, "tags": true, "tunnels": true}
	for k := range keys {
		names = append(names, k)
		switch {
		case forbiddenNewConnFields[strings.ToLower(k)] != "":
			forbidden = append(forbidden, k)
		case !allowed[k]:
			unknown = append(unknown, k)
		}
	}
	sort.Strings(names)
	sort.Strings(forbidden)
	sort.Strings(unknown)
	if len(forbidden) > 0 || len(unknown) > 0 {
		entry.Command = "new_connection fields=" + oneLine(strings.Join(names, ","), 300) // values are not logged
		if n, ok := keys["name"]; ok {
			var name string
			if json.Unmarshal(n, &name) == nil {
				entry.Connection = oneLine(name, 64)
			}
		}
		if len(forbidden) > 0 {
			var what []string
			seen := map[string]bool{}
			for _, f := range forbidden {
				if w := forbiddenNewConnFields[strings.ToLower(f)]; !seen[w] {
					seen[w] = true
					what = append(what, w)
				}
			}
			return reject(toolErr("rejected: agents cannot set %s (field %s). Create the connection without it; the user chooses the authentication and the access level in tussh.",
				strings.Join(what, ", "), strings.Join(forbidden, ", ")))
		}
		return reject(toolErr("rejected: unknown field %s. Allowed fields: name, host, port, user, description, tags, tunnels.", strings.Join(unknown, ", ")))
	}
	var a NewConnArgs
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return reject(toolErr("invalid arguments: %v", err))
	}
	a.Name, a.Host, a.User = strings.TrimSpace(a.Name), strings.TrimSpace(a.Host), strings.TrimSpace(a.User)
	entry.Connection = oneLine(a.Name, 64)
	entry.Command = newConnSummary(a)
	if a.Name == "" || a.Host == "" {
		return reject(toolErr("name and host are required"))
	}
	if len(a.Description) > 500 || strings.ContainsAny(a.Description, "\x00\x1b") {
		return reject(toolErr("description: at most 500 characters, no control characters"))
	}
	if len(a.Tags) > 16 || len(a.Tunnels) > 16 {
		return reject(toolErr("at most 16 tags and 16 tunnels"))
	}
	tunnels, err := config.ParseTunnels(strings.Join(a.Tunnels, ","))
	if err != nil {
		return reject(toolErr("%v (format: name=[bind:]local:host:port)", err))
	}
	for _, t := range a.Tunnels {
		if strings.Contains(t, ",") {
			return reject(toolErr("tunnel %q: one tunnel per array item", t))
		}
	}
	c := config.Connection{
		ID: config.NewID(), Name: a.Name, Host: a.Host, Port: a.Port, User: a.User, Description: strings.TrimSpace(a.Description),
		Tags: config.NormalizeTags(a.Tags), Tunnels: tunnels, Auth: config.AuthKey, AccessLevel: config.LevelNone,
		CreatedBy: config.CreatedByAgent, CreatedAgent: s.Agent, CreatedAt: time.Now().UTC().Truncate(time.Second), NeedsSetup: true,
	}
	if c.Port == 22 {
		c.Port = 0
	}
	if err := c.Validate(); err != nil {
		return reject(toolErr("%v", err))
	}
	_, err = config.Update(func(st *config.Store) error {
		pendingSetup := 0
		for _, o := range st.Connections {
			if strings.EqualFold(o.Name, c.Name) {
				return toolErr("a connection named %q already exists. Pick another name.", c.Name)
			}
			if o.NeedsSetup {
				pendingSetup++
			}
		}
		if pendingSetup >= MaxPendingSetup {
			return toolErr("%d connections created by agents are still waiting for the user's setup; ask the user to set them up or delete them in tussh first", pendingSetup)
		}
		_, err := st.Upsert(c)
		return err
	})
	if err != nil {
		if !IsToolError(err) {
			err = toolErr("cannot save the connection: %v", err)
		}
		return reject(err)
	}
	entry.Decision = audit.Created
	entry.Reasons = []string{"created with access level none and no credentials; needs setup by the user"}
	_ = audit.Append(entry)
	if !approval.TUIOpen() {
		if s.NotifyNewConn != nil {
			s.NotifyNewConn(s.Agent, c.Name)
		} else {
			st := config.LoadSettings()
			notify.NewConnection(notify.Options{Notification: !st.DisableNotifications, Herdr: !st.DisableHerdr}, s.Agent, c.Name)
		}
	}
	return &NewConnResponse{
		Connection: c.Name, Created: true, Usable: false, AccessLevel: config.LevelNone, NeedsSetup: true,
		Message: fmt.Sprintf("Connection %q was created, but it is NOT usable yet. The user has to open tussh, select it, press e and set "+
			"the authentication (key or password) and an access level. Until then it does not appear in list_connections and "+
			"run_command cannot use it. Tell the user it is waiting for their setup.", c.Name),
	}, nil
}

// newConnSummary is the audit log's "command" for new_connection (no secrets exist in these fields).
func newConnSummary(a NewConnArgs) string {
	parts := []string{"new_connection", "host=" + a.Host}
	if a.Port != 0 {
		parts = append(parts, fmt.Sprintf("port=%d", a.Port))
	}
	if a.User != "" {
		parts = append(parts, "user="+a.User)
	}
	if len(a.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(a.Tags, ","))
	}
	if len(a.Tunnels) > 0 {
		parts = append(parts, "tunnels="+strings.Join(a.Tunnels, ","))
	}
	if a.Description != "" {
		parts = append(parts, fmt.Sprintf("description=%q", a.Description))
	}
	return oneLine(strings.Join(parts, " "), 1000)
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}
