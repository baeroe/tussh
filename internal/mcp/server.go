// Package mcp is a minimal MCP server over stdio: newline-delimited JSON-RPC 2.0 with initialize, ping,
// tools/list and tools/call. Tool calls run concurrently (a call may block for minutes waiting for approval)
// and can be cancelled with notifications/cancelled.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/baeroe/tussh/internal/agent"
	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/sshrun"
)

// Version is reported in serverInfo.
var Version = "0.1.0"

var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const instructions = "SSH access to the user's servers through tussh. Call list_connections first; you can only see " +
	"connections the user shared with agents. Each has an access level: read-only (single allowlisted read-only " +
	"commands run immediately, anything else waits for the user's approval), approve-each (every command waits for " +
	"approval), trusted (commands run immediately). Sensitive commands (reading secrets, deleting, destructive " +
	"database/docker/service operations, permission changes, package removal, curl|sh, ...) always wait for approval. " +
	"Pass a short justification so the user can decide quickly. A denied or timed-out request must not be retried " +
	"unchanged and must never be worked around; ask the user instead. new_connection adds a connection to the " +
	"user's list (name, host, port, user, description, tags, tunnels only). It starts with access level none and " +
	"no credentials, so it is not usable and not listed until the user sets the authentication and an access " +
	"level in tussh; tell the user it is waiting for their setup."

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server is one MCP session.
type Server struct {
	out    io.Writer
	mu     sync.Mutex
	svc    *agent.Service
	wg     sync.WaitGroup
	cmu    sync.Mutex
	cancel map[string]context.CancelFunc
	logger *log.Logger
}

// New creates a server writing to out.
func New(out io.Writer, logw io.Writer) *Server {
	return &Server{out: out, svc: agent.New(""), cancel: map[string]context.CancelFunc{}, logger: log.New(logw, "tussh mcp: ", 0)}
}

// Service exposes the agent service (tests replace the notifier).
func (s *Server) Service() *agent.Service { return s.svc }

func (s *Server) send(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.out.Write(append(data, '\n'))
}

func (s *Server) reply(id json.RawMessage, result any) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) fail(id json.RawMessage, code int, msg string) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{code, msg}})
}

// Serve reads requests until EOF, then waits for running tool calls.
func (s *Server) Serve(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil {
			s.fail(json.RawMessage("null"), -32700, "parse error")
			continue
		}
		s.handle(m)
	}
	s.wg.Wait()
	return sc.Err()
}

func (s *Server) handle(m rpcMsg) {
	isNotification := len(m.ID) == 0 || string(m.ID) == "null"
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(m.Params, &p)
		version := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		if p.ClientInfo.Name != "" {
			name := p.ClientInfo.Name
			if p.ClientInfo.Version != "" {
				name += " " + p.ClientInfo.Version
			}
			s.svc.Agent = name
		}
		s.reply(m.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "tussh", "version": Version},
			"instructions":    instructions,
		})
	case "notifications/initialized", "initialized":
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		_ = json.Unmarshal(m.Params, &p)
		s.cmu.Lock()
		if c, ok := s.cancel[string(p.RequestID)]; ok {
			c()
		}
		s.cmu.Unlock()
	case "ping":
		s.reply(m.ID, map[string]any{})
	case "tools/list":
		s.reply(m.ID, map[string]any{"tools": tools()})
	case "tools/call":
		if isNotification {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		key := string(m.ID)
		s.cmu.Lock()
		s.cancel[key] = cancel
		s.cmu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.cmu.Lock()
				delete(s.cancel, key)
				s.cmu.Unlock()
				cancel()
			}()
			s.callTool(ctx, m)
		}()
	default:
		if !isNotification {
			s.fail(m.ID, -32601, "method not found: "+m.Method)
		}
	}
}

func schema(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func tools() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_connections",
			"description": "List the SSH connections the user shared with agents: name, description, tags and access level (read-only, approve-each, trusted). Contains no hosts or secrets.",
			"inputSchema": schema(map[string]any{}),
		},
		{
			"name": "run_command",
			"description": "Run one non-interactive shell command on a connection over ssh (no TTY, stdin closed). " +
				"Depending on the access level and the command it runs immediately or waits until the user approves or denies it in tussh " +
				"(auto-denied after the approval timeout, default 120 s). Returns exit_code, stdout, stderr (long output is truncated in the middle), timed_out.",
			"inputSchema": schema(map[string]any{
				"connection":    map[string]any{"type": "string", "description": "Connection name from list_connections."},
				"command":       map[string]any{"type": "string", "description": fmt.Sprintf("Command line for the remote shell (max %d characters).", classify.MaxCommandLen)},
				"justification": map[string]any{"type": "string", "description": "Why you need this command; shown to the user when approval is needed."},
				"timeout":       map[string]any{"type": "integer", "minimum": 1, "maximum": int(sshrun.MaxTimeout.Seconds()), "description": fmt.Sprintf("Seconds before the remote command is killed (default %d). Approval waiting time does not count.", int(sshrun.DefaultTimeout.Seconds()))},
			}, "connection", "command"),
		},
		{
			"name": "new_connection",
			"description": "Add a new SSH connection to the user's tussh list. You can set only name, host, port, user, description, tags and tunnels; " +
				"the access level, the authentication method, key files and secrets are set by the user and cannot be passed. " +
				"The connection is created with access level none and no credentials: it is NOT usable and does not appear in list_connections " +
				"until the user opens tussh, sets the authentication (key or password) and an access level. The user is notified.",
			"inputSchema": schema(map[string]any{
				"name":        map[string]any{"type": "string", "maxLength": 64, "pattern": "^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$", "description": "Unique connection name, e.g. shop-staging (letters, digits, _ . @ -)."},
				"host":        map[string]any{"type": "string", "maxLength": 255, "description": "Host name or IP address."},
				"port":        map[string]any{"type": "integer", "minimum": 1, "maximum": 65535, "description": "SSH port (default 22)."},
				"user":        map[string]any{"type": "string", "maxLength": 64, "description": "Remote user (empty: ssh default)."},
				"description": map[string]any{"type": "string", "maxLength": 500, "description": "Optional description; also shown to agents once the user shares the connection."},
				"tags":        map[string]any{"type": "array", "maxItems": 16, "items": map[string]any{"type": "string", "maxLength": 32}, "description": "Free-text tags, e.g. [\"prod\", \"shop\"]."},
				"tunnels":     map[string]any{"type": "array", "maxItems": 16, "items": map[string]any{"type": "string"}, "description": "Local port forwards, one per item: name=[bind:]local:host:port, e.g. mysql=3307:127.0.0.1:3306."},
			}, "name", "host"),
		},
	}
}

func textResult(v any, isError bool) map[string]any {
	var text string
	if s, ok := v.(string); ok {
		text = s
	} else {
		data, _ := json.MarshalIndent(v, "", "  ")
		text = string(data)
	}
	r := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
	if !isError {
		if _, ok := v.(string); !ok {
			r["structuredContent"] = v
		}
	}
	return r
}

func (s *Server) callTool(ctx context.Context, m rpcMsg) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		s.fail(m.ID, -32602, "invalid params")
		return
	}
	switch p.Name {
	case "list_connections":
		conns, err := s.svc.ListConnections()
		if err != nil {
			s.reply(m.ID, textResult(err.Error(), true))
			return
		}
		s.reply(m.ID, textResult(map[string]any{"connections": conns}, false))
	case "run_command":
		var a struct {
			Connection    string `json:"connection"`
			Command       string `json:"command"`
			Justification string `json:"justification"`
			Timeout       int    `json:"timeout"`
		}
		if len(p.Arguments) > 0 {
			if err := json.Unmarshal(p.Arguments, &a); err != nil {
				s.reply(m.ID, textResult("invalid arguments: "+err.Error(), true))
				return
			}
		}
		if a.Connection == "" || a.Command == "" {
			s.reply(m.ID, textResult("connection and command are required", true))
			return
		}
		res, err := s.svc.RunCommand(ctx, agent.RunRequest{Connection: a.Connection, Command: a.Command, Justification: a.Justification, TimeoutSec: a.Timeout})
		if err != nil {
			if !agent.IsToolError(err) {
				s.logger.Printf("run_command: %v", err)
			}
			s.reply(m.ID, textResult(err.Error(), true))
			return
		}
		s.reply(m.ID, textResult(res, false))
	case "new_connection":
		res, err := s.svc.NewConnection(p.Arguments)
		if err != nil {
			if !agent.IsToolError(err) {
				s.logger.Printf("new_connection: %v", err)
			}
			s.reply(m.ID, textResult(err.Error(), true))
			return
		}
		s.reply(m.ID, textResult(res, false))
	default:
		s.fail(m.ID, -32602, "unknown tool: "+p.Name)
	}
}
