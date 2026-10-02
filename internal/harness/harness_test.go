package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSnippets(t *testing.T) {
	s := map[string]Snippet{}
	for _, x := range Snippets("/Users/me/.local/bin/tussh") {
		s[x.Name] = x
	}
	if s["Claude Code"].Text != "claude mcp add --scope user tussh -- /Users/me/.local/bin/tussh mcp" {
		t.Fatal(s["Claude Code"].Text)
	}
	if s["Codex CLI"].Text != "codex mcp add tussh -- /Users/me/.local/bin/tussh mcp" {
		t.Fatal(s["Codex CLI"].Text)
	}
	var cursor struct {
		MCPServers map[string]struct {
			Type, Command string
			Args          []string
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(s["Cursor"].Text), &cursor); err != nil || cursor.MCPServers["tussh"].Args[0] != "mcp" || cursor.MCPServers["tussh"].Type != "stdio" {
		t.Fatalf("cursor: %v %+v", err, cursor)
	}
	var oc struct {
		MCP map[string]struct{ Command []string } `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(s["opencode"].Text), &oc); err != nil || len(oc.MCP["tussh"].Command) != 2 {
		t.Fatalf("opencode: %v", err)
	}
	if s["Gemini CLI"].Note == "" || s["Cursor"].Note == "" {
		t.Fatal("unverified notes missing")
	}
	if Snippets("/path with space/tussh")[0].Text != "claude mcp add --scope user tussh -- '/path with space/tussh' mcp" {
		t.Fatal("quoting")
	}
}

func TestRegistered(t *testing.T) {
	home := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(content), 0o600)
	}
	if r := Registered(home); len(r) != 5 || r[Claude] || r[Codex] {
		t.Fatalf("empty home: %v", r)
	}
	write(".claude.json", `{"mcpServers": {"tussh": {"command": "/x/tussh", "args": ["mcp"]}}, "projects": {}}`)
	write(".codex/config.toml", "model = \"o3\"\n\n[mcp_servers.tussh]\ncommand = \"/x/tussh\"\n")
	write(".gemini/settings.json", `{broken`)
	write(".config/opencode/opencode.json", "{\n  // comment\n  \"mcp\": {\"tussh\": {\"type\": \"local\"}}\n}")
	write(".cursor/mcp.json", `{"mcpServers": {"other": {}}}`)
	r := Registered(home)
	if !r[Claude] || !r[Codex] || r[Gemini] || !r[OpenCode] || r[Cursor] {
		t.Fatalf("detection: %v", r)
	}
	write(".codex/config.toml", "[mcp_servers.tusshx]\n")
	if Registered(home)[Codex] {
		t.Fatal("prefix matched")
	}
}
