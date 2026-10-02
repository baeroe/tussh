package policy

import (
	"testing"

	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/config"
)

func TestDecisionMatrix(t *testing.T) {
	c := classify.New()
	readOnly := c.Classify("ls *")           // read-only, not sensitive
	other := c.Classify("ls | wc -l")        // not read-only, not sensitive
	sensitive := c.Classify("rm -rf /tmp/x") // sensitive
	secretRO := c.Classify("cat .env")       // read-only AND sensitive

	cases := []struct {
		level string
		r     classify.Result
		want  Outcome
	}{
		{config.LevelNone, readOnly, Deny}, {config.LevelNone, other, Deny}, {config.LevelNone, sensitive, Deny},
		{config.LevelReadOnly, readOnly, Auto}, {config.LevelReadOnly, other, Approval}, {config.LevelReadOnly, sensitive, Approval},
		{config.LevelReadOnly, secretRO, Approval},
		{config.LevelApproveEach, readOnly, Approval}, {config.LevelApproveEach, other, Approval}, {config.LevelApproveEach, sensitive, Approval},
		{config.LevelTrusted, readOnly, Auto}, {config.LevelTrusted, other, Auto}, {config.LevelTrusted, sensitive, Approval},
		{config.LevelTrusted, secretRO, Approval},
		{"bogus", readOnly, Deny}, {"", readOnly, Deny},
	}
	for _, tc := range cases {
		d := Decide(tc.level, tc.r)
		if d.Outcome != tc.want {
			t.Errorf("level %q command %q: got %s want %s", tc.level, tc.r.Command, d.Outcome, tc.want)
		}
		if d.Outcome == Approval && len(d.Reasons) == 0 {
			t.Errorf("level %q command %q: approval without reasons", tc.level, tc.r.Command)
		}
	}
}

func TestCommandSent(t *testing.T) {
	c := classify.New()
	// read-only auto: the re-quoted form (no globbing on the remote side)
	if d := Decide(config.LevelReadOnly, c.Classify("ls *")); d.Command != "ls '*'" {
		t.Fatalf("read-only sends %q", d.Command)
	}
	// trusted: as-is (normal shell semantics)
	if d := Decide(config.LevelTrusted, c.Classify("ls *")); d.Command != "ls *" {
		t.Fatalf("trusted sends %q", d.Command)
	}
	// approval: exactly what the human saw
	if d := Decide(config.LevelReadOnly, c.Classify("ls | wc -l")); d.Command != "ls | wc -l" {
		t.Fatalf("approval sends %q", d.Command)
	}
}
