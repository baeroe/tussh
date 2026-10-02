//go:build ignore

// tui.go runs the real tussh TUI for the README screenshots (see docs/screenshots.sh) with one difference:
// the reachability probe is simulated, because the demo hosts (*.example) do not exist. Every other part
// (connections, approvals, history, forms, Setup) reads the sandbox files exactly like `tussh` does.
//
//	go build -o tussh-demo docs/demo/tui.go && ./tussh-demo [alerts [--popup]]
package main

import (
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/tui"
)

// down are the demo hosts shown as unreachable.
var down = map[string]bool{"pi.homelab.example": true}

func probe(host string, _ int) error {
	h := fnv.New32a()
	_, _ = h.Write([]byte(host))
	time.Sleep(time.Duration(15+h.Sum32()%60) * time.Millisecond) // a plausible latency per host
	if down[host] {
		time.Sleep(time.Second)
		return errors.New("timeout")
	}
	return nil
}

func main() {
	home, _ := os.UserHomeDir()
	opts := tui.Options{Tab: tui.TabConnections, Probe: probe, Bin: filepath.Join(home, ".local", "bin", "tussh")}
	if len(os.Args) > 1 && os.Args[1] == "alerts" {
		opts.Tab = tui.TabAlerts
		opts.ExitWhenDone = len(os.Args) > 2 && os.Args[2] == "--popup"
	}
	_, err := tea.NewProgram(tui.New(opts), tea.WithAltScreen()).Run()
	approval.ClearHeartbeat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tussh-demo:", err)
		os.Exit(1)
	}
}
