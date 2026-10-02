// Package policy turns an access level and a command classification into a decision.
//
//	level          read-only cmd   other cmd   sensitive (any level)
//	none           deny            deny        deny
//	read-only      auto            approval    approval
//	approve-each   approval        approval    approval
//	trusted        auto            auto        approval
package policy

import (
	"github.com/baeroe/tussh/internal/classify"
	"github.com/baeroe/tussh/internal/config"
)

// Outcome of a policy check.
type Outcome string

const (
	Auto     Outcome = "auto"
	Approval Outcome = "approval"
	Deny     Outcome = "deny"
)

// Decision is the outcome plus why.
type Decision struct {
	Outcome Outcome
	Reasons []string
	// Command is what gets sent to the remote shell: the re-quoted form for read-only auto runs,
	// otherwise the command exactly as the agent sent it (and as the human approved it).
	Command string
}

// Decide applies the access-level matrix.
func Decide(level string, r classify.Result) Decision {
	d := Decision{Command: r.Command}
	if !config.ValidLevel(level) {
		level = config.LevelNone
	}
	if level == config.LevelNone {
		d.Outcome = Deny
		d.Reasons = []string{"access level none: agents may not use this connection"}
		return d
	}
	if r.Sensitive() {
		d.Outcome = Approval
		d.Reasons = r.Reasons()
		return d
	}
	switch level {
	case config.LevelReadOnly:
		if r.ReadOnly {
			d.Outcome, d.Command = Auto, r.Normalized
			return d
		}
		d.Outcome = Approval
		d.Reasons = []string{"not read-only: " + r.NotReadOnly}
	case config.LevelApproveEach:
		d.Outcome = Approval
		d.Reasons = []string{"access level approve-each: every command needs approval"}
	case config.LevelTrusted:
		d.Outcome = Auto // sent as-is: trusted connections get normal shell semantics (globs, pipes)
	}
	return d
}
