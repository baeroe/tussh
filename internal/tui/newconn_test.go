package tui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/baeroe/tussh/internal/agent"
	"github.com/baeroe/tussh/internal/config"
)

// agentCreates runs the new_connection tool in-process, like an MCP process would.
func agentCreates(t *testing.T, args string) {
	t.Helper()
	svc := agent.New("claude-code 2.1")
	svc.NotifyNewConn = func(string, string) {}
	if _, err := svc.NewConnection(json.RawMessage(args)); err != nil {
		t.Fatal(err)
	}
}

func TestAgentCreatedConnectionInTUI(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	h := newHarness(t, TabConnections)
	addConns(t, h, config.Connection{Name: "homelab", Host: "nas.local", AccessLevel: config.LevelReadOnly})
	// the user starts editing homelab; meanwhile an agent adds a connection
	h.key("e")
	h.typeIn(fDescription, "my nas")
	time.Sleep(10 * time.Millisecond) // a different mtime for the file stamp
	agentCreates(t, `{"name":"shop-staging","host":"10.1.2.3","user":"deploy","tags":["staging"]}`)
	h.m.onTick(time.Now())
	if len(h.m.store.Connections) != 2 || !strings.Contains(h.m.status, "claude-code 2.1 added shop-staging · needs setup (e)") {
		t.Fatalf("live reload: %d %q", len(h.m.store.Connections), h.m.status)
	}
	if h.m.form == nil || h.m.form.inputs[fDescription].Value() != "my nas" {
		t.Fatal("reload touched the open form")
	}
	h.key("ctrl+s") // saving homelab must keep the agent's entry
	s, _ := config.Load()
	if len(s.Connections) != 2 {
		t.Fatalf("form save lost the agent's connection: %d", len(s.Connections))
	}
	if c, _ := s.ByName("homelab"); c.Description != "my nas" {
		t.Fatal("form save")
	}

	for _, size := range [][2]int{{110, 32}, {80, 24}} {
		h.m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for i, c := range h.m.rows {
			if c.Name == "shop-staging" {
				h.m.cursor[TabConnections] = i
			}
		}
		v := h.m.View()
		for i, l := range strings.Split(v, "\n") {
			if ansi.StringWidth(l) > size[0] {
				t.Fatalf("%v: line %d too wide", size, i)
			}
		}
		p := ansi.Strip(v)
		for _, want := range []string{"new · needs setup", "Created      by claude-code 2.1 at", "press e to choose the authentication"} {
			if !strings.Contains(p, want) {
				t.Errorf("%v: misses %q:\n%s", size, want, p)
			}
		}
	}
	// the Alerts tab lists it and e opens the form; saving clears needs_setup
	h.key("3")
	if !strings.Contains(ansi.Strip(h.m.View()), "New connections from agents (1) need setup") {
		t.Fatal("alerts section")
	}
	h.key("e")
	if h.m.form == nil || h.m.form.orig.Name != "shop-staging" {
		t.Fatal("e in Alerts")
	}
	h.focusField(fLevel)
	h.key("right", "ctrl+s")
	s, _ = config.Load()
	c, _ := s.ByName("shop-staging")
	if c.NeedsSetup || c.Level() != config.LevelReadOnly || c.CreatedBy != config.CreatedByAgent {
		t.Fatalf("after setup: %+v", c)
	}
	if strings.Contains(ansi.Strip(h.m.View()), "needs setup") {
		t.Fatal("badge after setup")
	}
}

func TestListKeysKeepAgentEntries(t *testing.T) {
	h := newHarness(t, TabConnections)
	addConns(t, h, config.Connection{Name: "a-box", Host: "a.example"})
	agentCreates(t, `{"name":"b-new","host":"b.example"}`)
	// the TUI has not reloaded yet; toggling favorite and the level must not drop b-new
	h.key("f", "l")
	s, _ := config.Load()
	if len(s.Connections) != 2 {
		t.Fatalf("lost: %d", len(s.Connections))
	}
	if c, _ := s.ByName("a-box"); !c.Favorite || c.Level() != config.LevelReadOnly {
		t.Fatalf("%+v", c)
	}
	h.m.cursor[TabConnections] = 1
	h.key("x", "y")
	s, _ = config.Load()
	if len(s.Connections) != 1 {
		t.Fatal("delete")
	}
}
