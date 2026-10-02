// Command tussh is an SSH connection manager TUI with access control for AI agents (MCP server).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/mcp"
	"github.com/baeroe/tussh/internal/secrets"
	"github.com/baeroe/tussh/internal/sshrun"
	"github.com/baeroe/tussh/internal/tui"
)

var version = "0.1.0"

const usage = `tussh - SSH connection manager with access control for AI agents

Usage:
  tussh                 open the TUI
  tussh alerts          open the TUI on the Alerts tab (pending approval requests)
  tussh alerts --popup  same, but quit once all shown requests are decided
  tussh mcp             run the MCP server on stdio (started by your agent harness)
  tussh pending         list pending approval requests (JSON)
  tussh approve ID      approve a pending request
  tussh deny ID         deny a pending request
  tussh askpass PROMPT  SSH_ASKPASS helper (used internally by ssh)
  tussh version

Register the MCP server, e.g. for Claude Code:
  claude mcp add --scope user tussh -- %s mcp
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// ssh runs SSH_ASKPASS with the prompt as the only argument.
	if os.Getenv("TUSSH_ASKPASS_MODE") == "1" {
		prompt := ""
		if len(args) > 0 {
			prompt = args[len(args)-1]
		}
		return askpass(prompt)
	}
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "":
		return runTUI(tui.Options{Tab: tui.TabConnections})
	case "alerts":
		popup := len(args) > 1 && args[1] == "--popup"
		return runTUI(tui.Options{Tab: tui.TabAlerts, ExitWhenDone: popup})
	case "mcp":
		srv := mcp.New(os.Stdout, os.Stderr)
		mcp.Version = version
		if err := srv.Serve(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "tussh mcp:", err)
			return 1
		}
		return 0
	case "askpass":
		return askpass(strings.Join(args[1:], " "))
	case "pending":
		data, _ := json.MarshalIndent(approval.Open().Pending(), "", "  ")
		fmt.Println(string(data))
		return 0
	case "approve", "deny":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "usage: tussh %s ID\n", cmd)
			return 2
		}
		d := approval.Approved
		if cmd == "deny" {
			d = approval.Denied
		}
		if err := approval.Open().Resolve(args[1], d, "cli", ""); err != nil {
			fmt.Fprintln(os.Stderr, "tussh:", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Println("tussh", version)
		return 0
	case "help", "--help", "-h":
		fmt.Printf(usage, sshrun.Self())
		return 0
	}
	fmt.Fprintf(os.Stderr, "tussh: unknown command %q\n\n", cmd)
	fmt.Fprintf(os.Stderr, usage, sshrun.Self())
	return 2
}

func askpass(prompt string) int {
	if err := sshrun.Askpass(prompt, secrets.Open(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runTUI(opts tui.Options) int {
	m := tui.New(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	approval.ClearHeartbeat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tussh:", err)
		return 1
	}
	return 0
}
