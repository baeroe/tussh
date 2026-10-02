// Package classify decides what an agent command is: read-only (strict allowlist) and/or sensitive
// (built-in and user rules). It is best-effort: it only sees the command line, never script contents or
// what a program does at runtime. When unsure it reports a finding so the command needs approval.
package classify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
)

// Result is the classification of one command.
type Result struct {
	Command string `json:"command"`
	// ReadOnly: passes the strict read-only allowlist. Normalized is then the re-quoted command to send.
	ReadOnly    bool      `json:"read_only"`
	NotReadOnly string    `json:"not_read_only_reason,omitempty"`
	Normalized  string    `json:"-"`
	Findings    []Finding `json:"findings,omitempty"`
}

// Sensitive reports whether any sensitive rule (or an "unsure" condition) matched.
func (r Result) Sensitive() bool { return len(r.Findings) > 0 }

// Reasons returns human-readable reasons.
func (r Result) Reasons() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, fmt.Sprintf("%s: %s", f.Category, f.Description))
	}
	return out
}

// UserRule is one entry of rules.json.
type UserRule struct {
	ID            string          `json:"id"`
	Description   string          `json:"description,omitempty"`
	Category      string          `json:"category,omitempty"`
	Pattern       string          `json:"pattern,omitempty"`
	Command       json.RawMessage `json:"command,omitempty"` // "name" or ["a", "b"]
	ArgsPattern   string          `json:"args_pattern,omitempty"`
	CaseSensitive bool            `json:"case_sensitive,omitempty"`

	commands []string
	re, args *regexp.Regexp
}

// RulesFile is the rules.json document.
type RulesFile struct {
	Rules []UserRule `json:"rules"`
}

// Classifier holds the compiled rules.
type Classifier struct {
	user     []UserRule
	rulesErr error
}

// New returns a classifier with only the built-in rules.
func New() *Classifier { return &Classifier{} }

// LoadRules reads a rules file. A missing file is fine. An invalid file makes every command sensitive
// (fail closed) and is reported by RulesError.
func LoadRules(file string) *Classifier {
	c := &Classifier{}
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return c
	}
	if err != nil {
		c.rulesErr = err
		return c
	}
	rules, err := ParseRules(data)
	if err != nil {
		c.rulesErr = fmt.Errorf("%s: %w", file, err)
		return c
	}
	c.user = rules
	return c
}

// RulesError is the error from loading the rules file, if any.
func (c *Classifier) RulesError() error { return c.rulesErr }

// UserRules returns the loaded user rules.
func (c *Classifier) UserRules() []UserRule { return c.user }

// ParseRules parses and compiles rules.json content.
func ParseRules(data []byte) ([]UserRule, error) {
	var f RulesFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.ID == "" {
			r.ID = fmt.Sprintf("user-%d", i+1)
		}
		if r.Category == "" {
			r.Category = CatUser
		}
		if r.Description == "" {
			r.Description = "user rule " + r.ID
		}
		flags := "(?i)"
		if r.CaseSensitive {
			flags = ""
		}
		if len(r.Command) > 0 {
			var one string
			if err := json.Unmarshal(r.Command, &one); err == nil {
				r.commands = []string{one}
			} else if err := json.Unmarshal(r.Command, &r.commands); err != nil {
				return nil, fmt.Errorf("rule %s: command must be a string or a list of strings", r.ID)
			}
			for _, c := range r.commands {
				if c == "" {
					return nil, fmt.Errorf("rule %s: empty command name", r.ID)
				}
			}
		}
		if r.Pattern == "" && len(r.commands) == 0 {
			return nil, fmt.Errorf("rule %s: needs pattern or command", r.ID)
		}
		if r.ArgsPattern != "" && len(r.commands) == 0 {
			return nil, fmt.Errorf("rule %s: args_pattern needs command", r.ID)
		}
		var err error
		if r.Pattern != "" {
			if r.re, err = regexp.Compile(flags + r.Pattern); err != nil {
				return nil, fmt.Errorf("rule %s: pattern: %v", r.ID, err)
			}
		}
		if r.ArgsPattern != "" {
			if r.args, err = regexp.Compile(flags + r.ArgsPattern); err != nil {
				return nil, fmt.Errorf("rule %s: args_pattern: %v", r.ID, err)
			}
		}
	}
	return f.Rules, nil
}

func (r UserRule) matchSimple(c simple) bool {
	if len(r.commands) == 0 {
		return false
	}
	hit := false
	for _, n := range r.commands {
		if c.name == n || c.name == path.Base(n) {
			hit = true
		}
	}
	if !hit {
		return false
	}
	return r.args == nil || r.args.MatchString(strings.Join(c.args, " "))
}

// Classify classifies one command line.
func (c *Classifier) Classify(command string) Result {
	res := Result{Command: command}
	if norm, err := CheckReadOnly(command); err == nil {
		res.ReadOnly, res.Normalized = true, norm
	} else {
		res.NotReadOnly = err.Error()
	}
	seen := map[string]bool{}
	add := func(f Finding) {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			res.Findings = append(res.Findings, f)
		}
	}
	if c.rulesErr != nil {
		add(Finding{"rules-file-invalid", CatUnsure, "the rules file is invalid, so every command needs approval: " + c.rulesErr.Error()})
	}
	if strings.TrimSpace(command) == "" {
		return res
	}
	if _, err := ShellSplit(command); err != nil {
		add(Finding{"unparseable", CatUnsure, "cannot parse the command line (" + err.Error() + ")"})
	}
	if strings.ContainsAny(command, "\x00") {
		add(Finding{"nul-byte", CatUnsure, "command contains a NUL byte"})
	}

	for _, r := range builtinReRules {
		if r.re.MatchString(command) {
			add(Finding{r.id, r.cat, r.desc})
		}
	}
	if updateWithoutWhere(command) {
		add(Finding{"sql-update-no-where", CatDatabase, "SQL UPDATE without WHERE"})
	}
	for _, r := range c.user {
		if r.re != nil && r.re.MatchString(command) {
			add(Finding{r.ID, r.Category, r.Description})
		}
	}

	for _, seg := range segments(command) {
		for _, f := range redirectFindings(seg) {
			add(f)
		}
		top, ok := toSimple(seg.words, seg)
		if !ok {
			continue
		}
		cands := []simple{top}
		if isExecutor(top) {
			// every trailing position may be the start of the executed command
			for i := range top.args {
				if s, ok := toSimple(top.args[i:], seg); ok {
					cands = append(cands, s)
				}
			}
		}
		for _, s := range cands {
			for _, r := range builtinCmdRules {
				if r.match(s) {
					add(Finding{r.id, r.cat, r.desc})
				}
			}
			for _, r := range c.user {
				if r.matchSimple(s) {
					add(Finding{r.ID, r.Category, r.Description})
				}
			}
		}
	}
	return res
}
