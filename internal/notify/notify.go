// Package notify tells the human about a new approval request when no tussh TUI is open:
// a macOS notification (osascript). It fails silently.
package notify

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Options control which channels are used.
type Options struct {
	Notification bool
}

// NewRequest notifies about a pending request.
func NewRequest(opts Options, connection, command string) {
	if opts.Notification && runtime.GOOS == "darwin" {
		macNotification("tussh: approval needed", connection+": "+short(command, 120))
	}
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// appleScriptString quotes s as an AppleScript string literal.
func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func macNotification(title, body string) {
	script := "display notification " + appleScriptString(body) + " with title " + appleScriptString(title) + ` sound name "Glass"`
	run(5*time.Second, "osascript", "-e", script)
}

func run(timeout time.Duration, name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	_ = cmd.Run()
}

// NewConnection notifies about a connection an agent created (it needs setup in tussh).
func NewConnection(opts Options, agent, connection string) {
	if agent == "" {
		agent = "An agent"
	}
	if opts.Notification && runtime.GOOS == "darwin" {
		macNotification("tussh: new connection needs setup", short(agent, 60)+" created "+short(connection, 64)+". Open tussh to set auth and access level.")
	}
}
