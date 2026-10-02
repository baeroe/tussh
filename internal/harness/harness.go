// Package harness renders MCP registration snippets for agent harnesses (ported from herdr-ssh).
package harness

import (
	"encoding/json"
	"strings"
)

// Snippet is one registration command or config fragment.
type Snippet struct {
	Name string // harness
	How  string // where to put it
	Text string
	Note string // verification caveat, if any
}

func shQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func pretty(v any) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

// Snippets returns the registration snippets for the tussh binary at bin (absolute path).
// Formats were checked against each harness's docs in October 2026 (see Note for what is unverified).
func Snippets(bin string) []Snippet {
	q := shQuote(bin)
	js, _ := json.Marshal(bin)
	return []Snippet{
		{"Claude Code", "run in a shell", "claude mcp add --scope user tussh -- " + q + " mcp", ""},
		{"Codex CLI", "run in a shell", "codex mcp add tussh -- " + q + " mcp", ""},
		{"Codex CLI (config)", "add to ~/.codex/config.toml", "[mcp_servers.tussh]\ncommand = " + string(js) + "\nargs = [\"mcp\"]", ""},
		{"Gemini CLI", "run in a shell", "gemini mcp add -s user tussh " + q + " mcp",
			"unverified: whether `gemini mcp add` defaults to stdio for a path"},
		{"Gemini CLI (config)", "merge into ~/.gemini/settings.json",
			pretty(map[string]any{"mcpServers": map[string]any{"tussh": map[string]any{"command": bin, "args": []string{"mcp"}}}}), ""},
		{"opencode", "merge into ~/.config/opencode/opencode.json",
			pretty(map[string]any{"$schema": "https://opencode.ai/config.json",
				"mcp": map[string]any{"tussh": map[string]any{"type": "local", "command": []string{bin, "mcp"}, "enabled": true}}}), ""},
		{"Cursor", "merge into ~/.cursor/mcp.json",
			pretty(map[string]any{"mcpServers": map[string]any{"tussh": map[string]any{"type": "stdio", "command": bin, "args": []string{"mcp"}}}}),
			"unverified: whether Cursor still accepts entries without \"type\""},
	}
}
