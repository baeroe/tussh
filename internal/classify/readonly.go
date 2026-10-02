package classify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Read-only classification, ported from herdr-ssh's strict readonly policy: a single command from an allowlist,
// no shell metacharacters at all (even inside quotes), argument restrictions for commands that could write,
// run programs or change state. A command that is not read-only is NOT blocked by tussh; it needs approval.

var forbiddenChars = []struct{ ch, label string }{
	{";", "';'"}, {"&", "'&'"}, {"|", "'|'"}, {"<", "'<'"}, {">", "'>'"}, {"`", "backtick"}, {"$", "'$'"},
	{"\\", "backslash"}, {"\n", "newline"}, {"\r", "carriage return"}, {"\x00", "NUL"},
}

// MaxCommandLen is the longest command accepted at all.
const MaxCommandLen = 4000

type argCheck func(args []string) string

func shortClusterHas(arg, letters string) bool {
	return strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], letters)
}

func longHas(arg string, names ...string) bool {
	if !strings.HasPrefix(arg, "--") {
		return false
	}
	n := strings.SplitN(arg[2:], "=", 2)[0]
	for _, x := range names {
		if n == x {
			return true
		}
	}
	return false
}

func deny(short string, long ...string) argCheck {
	return func(args []string) string {
		for _, a := range args {
			if (short != "" && shortClusterHas(a, short)) || longHas(a, long...) {
				return fmt.Sprintf("option %s is not allowed", a)
			}
		}
		return ""
	}
}

func checkFind(args []string) string {
	bad := map[string]bool{"-exec": true, "-execdir": true, "-ok": true, "-okdir": true, "-delete": true,
		"-fprint": true, "-fprint0": true, "-fprintf": true, "-fls": true}
	for _, a := range args {
		if bad[a] {
			return fmt.Sprintf("find %s is not allowed", a)
		}
	}
	return ""
}

func checkSubcommand(name string, allowed []string, extra func(sub string, args []string) string) argCheck {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	return func(args []string) string {
		var positional []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				positional = append(positional, a)
			}
		}
		if len(positional) == 0 || !set[positional[0]] {
			s := append([]string(nil), allowed...)
			sort.Strings(s)
			return fmt.Sprintf("%s: only these subcommands are allowed: %s", name, strings.Join(s, ", "))
		}
		if name == "docker" && strings.HasPrefix(args[0], "-") {
			return "docker: global options before the subcommand are not allowed"
		}
		if extra != nil {
			return extra(positional[0], args)
		}
		return ""
	}
}

func dockerExtra(sub string, args []string) string {
	if sub == "stats" {
		for _, a := range args {
			if a == "--no-stream" {
				return ""
			}
		}
		return "docker stats needs --no-stream"
	}
	return ""
}

func checkHostname(args []string) string {
	ok := map[string]bool{"-f": true, "-s": true, "-i": true, "-I": true, "-d": true, "-A": true, "--fqdn": true,
		"--short": true, "--ip-address": true, "--all-ip-addresses": true, "--domain": true}
	for _, a := range args {
		if !ok[a] {
			return "hostname: only display flags are allowed (no arguments)"
		}
	}
	return ""
}

var dateISORE = regexp.MustCompile(`^(-I|--iso-8601=|--rfc-3339=)(date|hours|minutes|seconds|ns)?$`)

func checkDate(args []string) string {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "+"):
		case a == "-u" || a == "--utc" || a == "--universal" || a == "-R" || a == "--rfc-email" || a == "-I":
		case dateISORE.MatchString(a):
		default:
			return "date: only +FORMAT, -u, -R and -I/--iso-8601/--rfc-3339 are allowed"
		}
	}
	return ""
}

// readOnlyCommands maps a command to its argument check (nil = any arguments).
var readOnlyCommands = map[string]argCheck{
	"cat": nil, "head": nil, "tail": nil, "wc": nil, "grep": nil, "egrep": nil, "fgrep": nil, "zcat": nil,
	"ls": nil, "stat": nil, "readlink": nil, "realpath": nil, "basename": nil, "dirname": nil,
	"md5sum": nil, "sha1sum": nil, "sha256sum": nil, "cut": nil, "echo": nil, "pwd": nil, "which": nil,
	"df": nil, "du": nil, "free": nil, "uptime": nil, "uname": nil, "whoami": nil, "id": nil, "groups": nil,
	"w": nil, "who": nil, "last": nil, "nproc": nil, "lscpu": nil, "lsblk": nil, "vmstat": nil,
	"ps": nil, "pgrep": nil, "lsof": nil, "netstat": nil,
	"ss":       deny("K", "kill"),
	"tree":     deny("oR"),
	"file":     deny("C", "compile"),
	"sort":     deny("o", "output", "compress-program"),
	"find":     checkFind,
	"hostname": checkHostname,
	"date":     checkDate,
	"journalctl": deny("", "rotate", "vacuum-size", "vacuum-time", "vacuum-files", "flush", "sync",
		"relinquish-var", "smart-relinquish-var", "setup-keys", "update-catalog"),
	"systemctl": checkSubcommand("systemctl", []string{"status", "is-active", "is-enabled", "is-failed", "list-units",
		"list-unit-files", "list-timers", "list-sockets", "show", "cat"}, nil),
	"docker": checkSubcommand("docker", []string{"ps", "images", "logs", "inspect", "version", "info", "stats"}, dockerExtra),
}

// ReadOnlyCommands lists the allowlist (sorted).
func ReadOnlyCommands() []string {
	var out []string
	for k := range readOnlyCommands {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CheckReadOnly validates a command against the read-only allowlist. On success it returns the command
// re-quoted word by word (no globbing, no variables on the remote side). On failure it returns the reason.
func CheckReadOnly(command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("empty command")
	}
	if len(command) > MaxCommandLen {
		return "", fmt.Errorf("command too long (max %d characters)", MaxCommandLen)
	}
	for _, f := range forbiddenChars {
		if strings.Contains(command, f.ch) {
			return "", fmt.Errorf("shell metacharacter %s (pipes, redirects, chaining, substitution and variables are never read-only)", f.label)
		}
	}
	argv, err := ShellSplit(command)
	if err != nil {
		return "", fmt.Errorf("cannot parse command: %v", err)
	}
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	name, args := argv[0], argv[1:]
	check, ok := readOnlyCommands[name]
	if !ok {
		hint := ""
		if strings.Contains(name, "/") {
			hint = " (use the bare command name, no path)"
		}
		return "", fmt.Errorf("command %q is not on the read-only allowlist%s", name, hint)
	}
	if check != nil {
		if p := check(args); p != "" {
			return "", fmt.Errorf("%s", p)
		}
	}
	return QuoteArgv(argv), nil
}
