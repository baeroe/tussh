// Package harness renders MCP registration snippets for agent harnesses (ported from herdr-ssh).
package harness

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Harness ids (Snippet.Harness, Registered).
const (
	Claude   = "claude"
	Codex    = "codex"
	Gemini   = "gemini"
	OpenCode = "opencode"
	Cursor   = "cursor"
)

// Snippet is one registration command or config fragment.
type Snippet struct {
	Harness string // harness id
	Name    string // display name
	How     string // where to put it
	Text    string
	Note    string // verification caveat, if any
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
		{Claude, "Claude Code", "run in a shell", "claude mcp add --scope user tussh -- " + q + " mcp", ""},
		{Codex, "Codex CLI", "run in a shell", "codex mcp add tussh -- " + q + " mcp", ""},
		{Codex, "Codex CLI (config)", "add to ~/.codex/config.toml", "[mcp_servers.tussh]\ncommand = " + string(js) + "\nargs = [\"mcp\"]", ""},
		{Gemini, "Gemini CLI", "run in a shell", "gemini mcp add -s user tussh " + q + " mcp",
			"unverified: whether `gemini mcp add` defaults to stdio for a path"},
		{Gemini, "Gemini CLI (config)", "merge into ~/.gemini/settings.json",
			pretty(map[string]any{"mcpServers": map[string]any{"tussh": map[string]any{"command": bin, "args": []string{"mcp"}}}}), ""},
		{OpenCode, "opencode", "merge into ~/.config/opencode/opencode.json",
			pretty(map[string]any{"$schema": "https://opencode.ai/config.json",
				"mcp": map[string]any{"tussh": map[string]any{"type": "local", "command": []string{bin, "mcp"}, "enabled": true}}}), ""},
		{Cursor, "Cursor", "merge into ~/.cursor/mcp.json",
			pretty(map[string]any{"mcpServers": map[string]any{"tussh": map[string]any{"type": "stdio", "command": bin, "args": []string{"mcp"}}}}),
			"unverified: whether Cursor still accepts entries without \"type\""},
	}
}

// Registered reports, per harness id, whether a "tussh" MCP server entry exists in that harness's user-level
// config under home. It only reads files (never runs a harness CLI); missing or invalid files count as
// not registered. Project-scoped registrations are not detected.
func Registered(home string) map[string]bool {
	out := map[string]bool{}
	jsonHas := func(rel string, path ...string) bool {
		data, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			return false
		}
		var v any
		if json.Unmarshal(stripJSONC(data), &v) != nil {
			return false
		}
		for _, k := range path {
			m, ok := v.(map[string]any)
			if !ok {
				return false
			}
			if v, ok = m[k]; !ok {
				return false
			}
		}
		return v != nil
	}
	out[Claude] = jsonHas(".claude.json", "mcpServers", "tussh")
	out[Gemini] = jsonHas(filepath.Join(".gemini", "settings.json"), "mcpServers", "tussh")
	out[OpenCode] = jsonHas(filepath.Join(".config", "opencode", "opencode.json"), "mcp", "tussh") ||
		jsonHas(filepath.Join(".config", "opencode", "opencode.jsonc"), "mcp", "tussh")
	out[Cursor] = jsonHas(filepath.Join(".cursor", "mcp.json"), "mcpServers", "tussh")
	out[Codex] = tomlHasTable(filepath.Join(home, ".codex", "config.toml"))
	return out
}

var codexTableRE = regexp.MustCompile(`^\s*\[\s*mcp_servers\s*\.\s*("tussh"|'tussh'|tussh)\s*\]\s*(#.*)?$`)

func tomlHasTable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if codexTableRE.MatchString(sc.Text()) {
			return true
		}
	}
	return false
}

// stripJSONC removes // and /* */ comments outside strings (opencode and Cursor accept JSONC).
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		} else if c == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				i++
			}
			continue
		} else if c == '/' && i+1 < len(b) && b[i+1] == '*' {
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}
