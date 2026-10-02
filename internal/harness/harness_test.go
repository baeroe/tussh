package harness

import (
	"encoding/json"
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
