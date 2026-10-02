// Package notify tells the human about a new approval request when no tussh TUI is open:
// a macOS notification (osascript) and, if herdr is available, the herdr-tussh "alerts" action,
// which pops up `tussh alerts` inside herdr. Everything fails silently.
package notify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// HerdrAction is the plugin action that opens the alerts popup.
const HerdrAction = "herdr-tussh.alerts"

// Options control which channels are used.
type Options struct {
	Notification bool
	Herdr        bool
}

// NewRequest notifies about a pending request.
func NewRequest(opts Options, connection, command string) {
	if opts.Notification && runtime.GOOS == "darwin" {
		macNotification("tussh: approval needed", connection+": "+short(command, 120))
	}
	if opts.Herdr {
		InvokeHerdr()
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

// HerdrBin finds herdr: $HERDR_BIN_PATH, `herdr` on PATH, or ~/.local/bin/herdr. Empty if none.
func HerdrBin() string {
	if b := os.Getenv("HERDR_BIN_PATH"); b != "" {
		if _, err := os.Stat(b); err == nil {
			return b
		}
	}
	if b, err := exec.LookPath("herdr"); err == nil {
		return b
	}
	if h, err := os.UserHomeDir(); err == nil {
		b := filepath.Join(h, ".local", "bin", "herdr")
		if _, err := os.Stat(b); err == nil {
			return b
		}
	}
	return ""
}

// InvokeHerdr runs the herdr-tussh alerts action. Without a running herdr server this simply fails.
func InvokeHerdr() {
	if b := HerdrBin(); b != "" {
		run(5*time.Second, b, "plugin", "action", "invoke", HerdrAction)
	}
}

func run(timeout time.Duration, name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	_ = cmd.Run()
}
