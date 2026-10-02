package main

// End-to-end tests: the real tussh binary runs `tussh mcp` as a stdio subprocess with temp config/state dirs,
// a file keyring and a fake ssh. Approval requests are resolved by the test through the on-disk queue,
// exactly like the TUI does.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
)

var tusshBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tussh-bin-")
	if err != nil {
		panic(err)
	}
	tusshBin = filepath.Join(dir, "tussh")
	out, err := exec.Command("go", "build", "-o", tusshBin, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const fakeSSH = `#!/bin/sh
last=""
for a in "$@"; do last="$a"; done
case "$last" in
  askpass) "$SSH_ASKPASS" "tester@host's password: "; exit $? ;;
  sleepy) sleep 30 ;;
esac
printf 'REMOTE %s\n' "$last"
exit 0
`

// sandbox is a temp tussh environment shared by the test process and the subprocess.
type sandbox struct {
	dir, config, state, keyring string
	env                         []string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	dir := t.TempDir()
	sb := &sandbox{dir: dir, config: filepath.Join(dir, "config"), state: filepath.Join(dir, "state"), keyring: filepath.Join(dir, "keyring.json")}
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(fakeSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	sb.env = append(cleanEnv(), "TUSSH_CONFIG_DIR="+sb.config, "TUSSH_STATE_DIR="+sb.state,
		"TUSSH_KEYRING=file:"+sb.keyring, "TUSSH_SSH_BIN="+ssh, "TUSSH_NO_NOTIFY=1")
	// the test process uses the same dirs to resolve approvals and read the audit log
	t.Setenv("TUSSH_CONFIG_DIR", sb.config)
	t.Setenv("TUSSH_STATE_DIR", sb.state)
	t.Setenv("TUSSH_KEYRING", "file:"+sb.keyring)
	return sb
}

func cleanEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "TUSSH_") || strings.HasPrefix(e, "HERDR_") || strings.HasPrefix(e, "SSH_ASKPASS") {
			continue
		}
		env = append(env, e)
	}
	return env
}

func (sb *sandbox) addConnections(t *testing.T, conns ...config.Connection) {
	t.Helper()
	s, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range conns {
		if _, err := s.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

// --- MCP client -------------------------------------------------------------------------

type mcpClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	mu     sync.Mutex
	nextID int
	waits  map[int]chan map[string]any
	stderr strings.Builder
}

func startMCP(t *testing.T, env []string) *mcpClient {
	t.Helper()
	cmd := exec.Command(tusshBin, "mcp")
	cmd.Env = env
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	c := &mcpClient{t: t, cmd: cmd, stdin: stdin, waits: map[int]chan map[string]any{}}
	cmd.Stderr = &c.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var msg map[string]any
			if json.Unmarshal(sc.Bytes(), &msg) != nil {
				continue
			}
			id, ok := msg["id"].(float64)
			if !ok {
				continue
			}
			c.mu.Lock()
			ch := c.waits[int(id)]
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
		}
	}()
	t.Cleanup(c.close)
	return c
}

func (c *mcpClient) close() {
	c.stdin.Close()
	done := make(chan struct{})
	go func() { c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.cmd.Process.Kill()
	}
}

// send returns a channel for the response.
func (c *mcpClient) send(method string, params any) chan map[string]any {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan map[string]any, 1)
	c.waits[id] = ch
	c.mu.Unlock()
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if _, err := c.stdin.Write(append(data, '\n')); err != nil {
		c.t.Fatal(err)
	}
	return ch
}

func (c *mcpClient) wait(ch chan map[string]any, timeout time.Duration) map[string]any {
	c.t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(timeout):
		c.t.Fatalf("no MCP response within %s; stderr: %s", timeout, c.stderr.String())
	}
	return nil
}

func (c *mcpClient) request(method string, params any) map[string]any {
	c.t.Helper()
	return c.wait(c.send(method, params), 20*time.Second)
}

// toolResult extracts (isError, text, structured) from a tools/call response.
func toolResult(t *testing.T, msg map[string]any) (bool, string, map[string]any) {
	t.Helper()
	res, ok := msg["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", msg)
	}
	isErr, _ := res["isError"].(bool)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	sc, _ := res["structuredContent"].(map[string]any)
	return isErr, text, sc
}

func (c *mcpClient) call(name string, args map[string]any) (bool, string, map[string]any) {
	c.t.Helper()
	return toolResult(c.t, c.request("tools/call", map[string]any{"name": name, "arguments": args}))
}

func (c *mcpClient) init() {
	c.t.Helper()
	r := c.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "test-harness", "version": "1.0"}})
	res := r["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || res["serverInfo"].(map[string]any)["name"] != "tussh" {
		c.t.Fatalf("initialize: %v", r)
	}
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	c.stdin.Write(append(data, '\n'))
}

// awaitPending polls the queue until a request for command shows up.
func awaitPending(t *testing.T, command string) approval.Request {
	t.Helper()
	q := approval.Open()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range q.Pending() {
			if r.Command == command {
				return r
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no pending request for %q", command)
	return approval.Request{}
}

var (
	connRO      = config.Connection{Name: "ro", Host: "ro.example", Auth: config.AuthKey, AccessLevel: config.LevelReadOnly, Tags: []string{"test"}, Description: "read-only box"}
	connEach    = config.Connection{Name: "each", Host: "each.example", Auth: config.AuthKey, AccessLevel: config.LevelApproveEach}
	connTrusted = config.Connection{Name: "trusted", Host: "trusted.example", Auth: config.AuthKey, AccessLevel: config.LevelTrusted}
	connNone    = config.Connection{Name: "secret-box", Host: "none.example", Auth: config.AuthKey, AccessLevel: config.LevelNone}
)

func TestMCPHandshakeAndList(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connRO, connEach, connTrusted, connNone)
	c := startMCP(t, sb.env)
	c.init()
	if r := c.request("ping", map[string]any{}); r["result"] == nil {
		t.Fatalf("ping: %v", r)
	}
	if r := c.request("nope/method", nil); r["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("unknown method: %v", r)
	}
	r := c.request("tools/list", map[string]any{})
	var names []string
	for _, tool := range r["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "list_connections,run_command,new_connection" {
		t.Fatalf("tools: %v", names)
	}
	isErr, text, sc := c.call("list_connections", map[string]any{})
	if isErr {
		t.Fatal(text)
	}
	conns := sc["connections"].([]any)
	if len(conns) != 3 {
		t.Fatalf("expected 3 visible connections: %s", text)
	}
	if strings.Contains(text, "secret-box") || strings.Contains(text, "example") || strings.Contains(text, "host") {
		t.Fatalf("list leaks hidden connection or host: %s", text)
	}
	if !strings.Contains(text, `"access_level": "read-only"`) || !strings.Contains(text, "read-only box") {
		t.Fatalf("list: %s", text)
	}
}

func TestMCPReadOnlyAutoAndNone(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connRO, connNone)
	c := startMCP(t, sb.env)
	c.init()
	isErr, text, sc := c.call("run_command", map[string]any{"connection": "ro", "command": "ls -la *.log"})
	if isErr {
		t.Fatal(text)
	}
	if sc["decision"] != "auto" || sc["exit_code"].(float64) != 0 || sc["stdout"] != "REMOTE ls -la '*.log'\n" {
		t.Fatalf("auto run: %s", text)
	}
	isErr, text, _ = c.call("run_command", map[string]any{"connection": "secret-box", "command": "uptime"})
	if !isErr || !strings.Contains(text, "unknown connection") {
		t.Fatalf("none level: %v %s", isErr, text)
	}
	isErr, text, _ = c.call("run_command", map[string]any{"connection": "missing", "command": "uptime"})
	if !isErr || !strings.Contains(text, "unknown connection") {
		t.Fatalf("unknown: %s", text)
	}
	entries, _ := audit.Read(0)
	if len(entries) != 3 || entries[2].Decision != audit.Auto || entries[2].ExitCode == nil || entries[1].Decision != audit.Blocked {
		t.Fatalf("audit: %+v", entries)
	}
	if entries[2].Agent != "test-harness 1.0" {
		t.Fatalf("agent name: %q", entries[2].Agent)
	}
}

func TestMCPApprovalApproveAndDeny(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connRO, connEach, connTrusted)
	c := startMCP(t, sb.env)
	c.init()
	q := approval.Open()

	// read-only level, non-read-only command -> approval -> approve
	ch := c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{
		"connection": "ro", "command": "ls | wc -l", "justification": "count files"}})
	r := awaitPending(t, "ls | wc -l")
	if r.Connection != "ro" || r.Justification != "count files" || r.Agent != "test-harness 1.0" || len(r.Reasons) == 0 ||
		!strings.Contains(r.Reasons[0], "not read-only") {
		t.Fatalf("request: %+v", r)
	}
	// other calls are not blocked while one waits
	if isErr, text, _ := c.call("list_connections", map[string]any{}); isErr {
		t.Fatal(text)
	}
	if err := q.Resolve(r.ID, approval.Approved, "test", ""); err != nil {
		t.Fatal(err)
	}
	isErr, text, sc := toolResult(t, c.wait(ch, 20*time.Second))
	if isErr || sc["decision"] != "approved" || sc["stdout"] != "REMOTE ls | wc -l\n" {
		t.Fatalf("approved run: %s", text)
	}

	// approve-each: even a read-only command needs approval -> deny
	ch = c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "each", "command": "uptime"}})
	r = awaitPending(t, "uptime")
	q.Resolve(r.ID, approval.Denied, "test", "")
	isErr, text, _ = toolResult(t, c.wait(ch, 20*time.Second))
	if !isErr || !strings.Contains(text, "denied by the user") {
		t.Fatalf("deny: %s", text)
	}

	// trusted: normal commands run automatically
	isErr, text, sc = c.call("run_command", map[string]any{"connection": "trusted", "command": "cd /srv && make build"})
	if isErr || sc["decision"] != "auto" {
		t.Fatalf("trusted auto: %s", text)
	}
	// trusted: sensitive command needs approval
	ch = c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "trusted", "command": "rm -rf /srv/cache"}})
	r = awaitPending(t, "rm -rf /srv/cache")
	if !strings.Contains(strings.Join(r.Reasons, " "), "delete") {
		t.Fatalf("reasons: %v", r.Reasons)
	}
	q.Resolve(r.ID, approval.Denied, "test", "")
	if isErr, text, _ := toolResult(t, c.wait(ch, 20*time.Second)); !isErr {
		t.Fatalf("sensitive deny: %s", text)
	}

	entries, _ := audit.Read(0)
	var decisions []string
	for i := len(entries) - 1; i >= 0; i-- {
		decisions = append(decisions, entries[i].Decision)
	}
	if strings.Join(decisions, ",") != "approved,denied,auto,denied" {
		t.Fatalf("audit decisions: %v", decisions)
	}
	if len(q.Pending()) != 0 {
		t.Fatal("queue not empty")
	}
}

func TestMCPApprovalTimeout(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connEach)
	c := startMCP(t, append(sb.env, "TUSSH_APPROVAL_TIMEOUT=1"))
	c.init()
	start := time.Now()
	isErr, text, _ := c.call("run_command", map[string]any{"connection": "each", "command": "uptime"})
	if !isErr || !strings.Contains(text, "denied automatically") {
		t.Fatalf("timeout: %s", text)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("took too long")
	}
	entries, _ := audit.Read(1)
	if entries[0].Decision != audit.Timeout {
		t.Fatalf("audit: %+v", entries[0])
	}
}

func TestMCPPasswordViaAskpass(t *testing.T) {
	sb := newSandbox(t)
	pw := connTrusted
	pw.Name, pw.Auth, pw.HasPassword, pw.ID = "pw", config.AuthPassword, true, "aaaa1111"
	sb.addConnections(t, pw)
	kr := secrets.Open()
	if err := kr.Set(secrets.Account(pw.ID, secrets.KindPassword), "hunter2"); err != nil {
		t.Fatal(err)
	}
	c := startMCP(t, sb.env)
	c.init()
	// the fake ssh calls $SSH_ASKPASS (= the tussh binary) and prints what it returns
	isErr, text, sc := c.call("run_command", map[string]any{"connection": "pw", "command": "askpass"})
	if isErr || sc["stdout"] != "hunter2\n" {
		t.Fatalf("askpass: %s", text)
	}
	// the token is gone afterwards
	entries, _ := os.ReadDir(filepath.Join(sb.state, "askpass"))
	if len(entries) != 0 {
		t.Fatalf("askpass tokens left: %d", len(entries))
	}
	data, _ := os.ReadFile(filepath.Join(sb.config, "connections.json"))
	auditData, _ := os.ReadFile(filepath.Join(sb.state, "audit.jsonl"))
	if strings.Contains(string(data), "hunter2") || strings.Contains(string(auditData), "hunter2") {
		t.Fatal("secret leaked into config or audit log")
	}
}

func TestMCPBrokenConfigFailsClosed(t *testing.T) {
	sb := newSandbox(t)
	os.MkdirAll(sb.config, 0o700)
	os.WriteFile(filepath.Join(sb.config, "connections.json"), []byte("{broken"), 0o600)
	c := startMCP(t, sb.env)
	c.init()
	if isErr, text, _ := c.call("list_connections", map[string]any{}); !isErr || !strings.Contains(text, "config error") {
		t.Fatalf("broken config: %s", text)
	}
}

func TestMCPCancelDeniesPending(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connEach)
	c := startMCP(t, sb.env)
	c.init()
	ch := c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "each", "command": "uptime"}})
	awaitPending(t, "uptime")
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": c.nextID}})
	c.stdin.Write(append(data, '\n'))
	if isErr, text, _ := toolResult(t, c.wait(ch, 10*time.Second)); !isErr {
		t.Fatalf("cancelled: %s", text)
	}
	if len(approval.Open().Pending()) != 0 {
		t.Fatal("cancelled request still pending")
	}
}

func TestCLI(t *testing.T) {
	sb := newSandbox(t)
	out, err := exec.Command(tusshBin, "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "tussh ") {
		t.Fatalf("version: %s %v", out, err)
	}
	cmd := exec.Command(tusshBin, "pending")
	cmd.Env = sb.env
	if out, err := cmd.Output(); err != nil || strings.TrimSpace(string(out)) != "null" && strings.TrimSpace(string(out)) != "[]" {
		t.Fatalf("pending: %s %v", out, err)
	}
	cmd = exec.Command(tusshBin, "askpass", "password: ")
	cmd.Env = sb.env
	if out, err := cmd.Output(); err == nil {
		t.Fatalf("askpass without token must fail, printed %q", out)
	}
	if err := exec.Command(tusshBin, "bogus").Run(); err == nil {
		t.Fatal("unknown command must fail")
	}
}

func TestMCPRememberedCommand(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connEach)
	s, _ := config.Load()
	each, _ := s.ByName("each")
	if _, err := allow.Add(each.ID, each.Name, "systemctl reload nginx", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := allow.Add(each.ID, each.Name, "uptime", -time.Minute, "test"); err != nil {
		t.Fatal(err)
	}
	c := startMCP(t, sb.env)
	c.init()
	isErr, text, sc := c.call("run_command", map[string]any{"connection": "each", "command": "systemctl reload nginx"})
	if isErr || sc["decision"] != "approved" || sc["stdout"] != "REMOTE systemctl reload nginx\n" {
		t.Fatalf("remembered: %s", text)
	}
	if len(approval.Open().Pending()) != 0 {
		t.Fatal("a remembered command must not create a request")
	}
	// expired: asks again; the deny note reaches the agent
	ch := c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "each", "command": "uptime"}})
	r := awaitPending(t, "uptime")
	approval.Open().Resolve(r.ID, approval.Denied, "test", "not now, the box is under maintenance")
	isErr, text, _ = toolResult(t, c.wait(ch, 20*time.Second))
	if !isErr || !strings.Contains(text, "not now, the box is under maintenance") {
		t.Fatalf("deny note: %s", text)
	}
	entries, _ := audit.Read(0)
	if entries[1].DecidedBy != "remembered" || entries[1].Stdout == "" || entries[0].Note == "" {
		t.Fatalf("audit: %+v", entries)
	}
	if isErr, text, _ := c.call("list_connections", map[string]any{}); isErr || strings.Contains(text, `"group"`) {
		t.Fatalf("list: %s", text)
	}
}

func TestMCPNewConnection(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connRO, connNone)
	c := startMCP(t, sb.env)
	c.init()

	// the schema has no access level, auth, key or secret fields and allows nothing else
	r := c.request("tools/list", map[string]any{})
	var schema map[string]any
	for _, tool := range r["result"].(map[string]any)["tools"].([]any) {
		if tm := tool.(map[string]any); tm["name"] == "new_connection" {
			schema = tm["inputSchema"].(map[string]any)
		}
	}
	if schema == nil || schema["additionalProperties"] != false {
		t.Fatalf("schema: %v", schema)
	}
	var props []string
	for k := range schema["properties"].(map[string]any) {
		props = append(props, k)
	}
	for _, bad := range []string{"access_level", "auth", "key_path", "password", "passphrase"} {
		if _, ok := schema["properties"].(map[string]any)[bad]; ok {
			t.Fatalf("schema offers %s: %v", bad, props)
		}
	}

	// smuggled fields are rejected, nothing is written, and secret values never reach the log
	for _, args := range []map[string]any{
		{"name": "x1", "host": "h.example", "access_level": "trusted"},
		{"name": "x2", "host": "h.example", "password": "hunter2-secret"},
		{"name": "x3", "host": "h.example", "passphrase": "pp-secret"},
		{"name": "x4", "host": "h.example", "key_path": "~/.ssh/id_ed25519"},
		{"name": "x5", "host": "h.example", "auth": "password"},
		{"name": "x6", "host": "h.example", "favourite": true},
	} {
		isErr, text, _ := c.call("new_connection", args)
		if !isErr || !strings.Contains(text, "rejected") {
			t.Fatalf("%v: %v %s", args, isErr, text)
		}
	}
	for _, args := range []map[string]any{
		{"host": "h.example"},
		{"name": "bad name", "host": "h.example"},
		{"name": "t1", "host": "h.example", "tunnels": []string{"db=3307:127.0.0.1"}},
		{"name": "t2", "host": "h.example", "tunnels": []string{"db=99999:127.0.0.1:3306"}},
		{"name": "t3", "host": "-oProxyCommand=x"},
		{"name": "RO", "host": "h.example"}, // duplicate (case-insensitive)
		{"name": "secret-box", "host": "h.example"},
	} {
		if isErr, text, _ := c.call("new_connection", args); !isErr {
			t.Fatalf("%v accepted: %s", args, text)
		}
	}
	if isErr, text, _ := c.call("new_connection", map[string]any{"name": "ro", "host": "h.example"}); !isErr || !strings.Contains(text, "already exists") {
		t.Fatalf("duplicate: %s", text)
	}
	s, _ := config.Load()
	if len(s.Connections) != 2 {
		t.Fatalf("rejected calls wrote connections: %d", len(s.Connections))
	}

	isErr, text, sc := c.call("new_connection", map[string]any{"name": "shop-staging", "host": "10.1.2.3", "port": 2222, "user": "deploy",
		"description": "staging shop", "tags": []string{"staging", "shop"}, "tunnels": []string{"mysql=3307:127.0.0.1:3306"}})
	if isErr || sc["usable"] != false || sc["needs_setup"] != true || sc["access_level"] != "none" || !strings.Contains(text, "NOT usable") {
		t.Fatalf("create: %v %s", isErr, text)
	}
	s, _ = config.Load()
	got, ok := s.ByName("shop-staging")
	if !ok || got.Level() != config.LevelNone || !got.NeedsSetup || got.CreatedBy != "agent" || got.CreatedAgent != "test-harness 1.0" ||
		got.CreatedAt.IsZero() || got.Port != 2222 || got.User != "deploy" || len(got.Tunnels) != 1 || got.HasPassword || got.HasPassphrase || got.KeyPath != "" {
		t.Fatalf("stored: %+v", got)
	}
	// invisible to agents until the user sets it up
	_, text, _ = c.call("list_connections", map[string]any{})
	if strings.Contains(text, "shop-staging") {
		t.Fatal("new connection is listed")
	}
	if isErr, text, _ := c.call("run_command", map[string]any{"connection": "shop-staging", "command": "uptime"}); !isErr || !strings.Contains(text, "unknown connection") {
		t.Fatalf("usable: %s", text)
	}

	entries, _ := audit.Read(0)
	created, blocked := 0, 0
	for _, e := range entries {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "pp-secret") {
			t.Fatalf("secret in audit log: %s", raw)
		}
		switch {
		case e.Decision == audit.Created && e.Connection == "shop-staging":
			created++
			if !strings.Contains(e.Command, "host=10.1.2.3") || e.Agent != "test-harness 1.0" {
				t.Fatalf("audit: %+v", e)
			}
		case e.Decision == audit.Blocked && strings.HasPrefix(e.Command, "new_connection"):
			blocked++
		}
	}
	if created != 1 || blocked != 14 {
		t.Fatalf("audit: %d created, %d blocked", created, blocked)
	}
}

// TestMCPNewConnectionConcurrentWrites: agent calls (in the MCP subprocess) and TUI-style writes (config.Update in
// this process) run at the same time; no entry is lost.
func TestMCPNewConnectionConcurrentWrites(t *testing.T) {
	sb := newSandbox(t)
	sb.addConnections(t, connRO)
	c := startMCP(t, sb.env)
	c.init()
	var wg sync.WaitGroup
	errs := make(chan string, 40)
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if isErr, text, _ := c.call("new_connection", map[string]any{"name": fmt.Sprintf("agent-%d", i), "host": "a.example"}); isErr {
				errs <- text
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			_, err := config.Update(func(s *config.Store) error {
				ro, _ := s.ByName("ro")
				ro.Favorite = !ro.Favorite
				if _, err := s.Upsert(ro); err != nil {
					return err
				}
				_, err := s.Upsert(config.Connection{Name: fmt.Sprintf("user-%d", i), Host: "u.example", Auth: config.AuthKey, AccessLevel: config.LevelNone})
				return err
			})
			if err != nil {
				errs <- err.Error()
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	s, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Connections) != 21 {
		t.Fatalf("expected 21 connections, got %d", len(s.Connections))
	}
}
