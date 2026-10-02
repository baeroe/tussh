// Package sshconfig lists concrete Host aliases from ~/.ssh/config (read-only) and resolves them with `ssh -G`
// for importing into tussh. Ported from herdr-ssh.
package sshconfig

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Host is one alias with the values ssh would use.
type Host struct {
	Alias        string
	HostName     string
	User         string
	Port         int
	IdentityFile string
}

var (
	lineRE  = regexp.MustCompile(`^([A-Za-z]+)\s*(?:=\s*|\s+)(.*)$`)
	aliasRE = regexp.MustCompile(`^[A-Za-z0-9_.@%+][A-Za-z0-9_.@%+-]*$`)
)

// DefaultPath is ~/.ssh/config.
func DefaultPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".ssh", "config")
}

func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quote := false
	in := false
	for _, c := range s {
		switch {
		case c == '"':
			quote = !quote
			in = true
		case (c == ' ' || c == '\t') && !quote:
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case c == '#' && !quote && !in:
			if in {
				out = append(out, cur.String())
			}
			return out
		default:
			cur.WriteRune(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// Parse returns concrete aliases (no wildcards/negations/Match), following Include, first value wins.
func Parse(path string) []Host {
	hosts := map[string]*Host{}
	var order []string
	seen := map[string]bool{}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || depth > 16 || seen[real] {
			return
		}
		seen[real] = true
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		base := filepath.Dir(p)
		var current []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			m := lineRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key, args := strings.ToLower(m[1]), splitArgs(m[2])
			switch key {
			case "host":
				current = nil
				for _, a := range args {
					if strings.ContainsAny(a, "*?!") || !aliasRE.MatchString(a) {
						continue
					}
					if _, ok := hosts[a]; !ok {
						hosts[a] = &Host{Alias: a}
						order = append(order, a)
					}
					current = append(current, a)
				}
			case "match":
				current = nil
			case "include":
				for _, pat := range args {
					if strings.HasPrefix(pat, "~/") {
						h, _ := os.UserHomeDir()
						pat = filepath.Join(h, pat[2:])
					}
					if !filepath.IsAbs(pat) {
						pat = filepath.Join(base, pat)
					}
					matches, _ := filepath.Glob(pat)
					sort.Strings(matches)
					for _, inc := range matches {
						if st, err := os.Stat(inc); err == nil && !st.IsDir() {
							walk(inc, depth+1)
						}
					}
				}
			case "hostname", "user", "port", "identityfile":
				if len(args) == 0 {
					continue
				}
				for _, a := range current {
					h := hosts[a]
					switch key {
					case "hostname":
						if h.HostName == "" {
							h.HostName = args[0]
						}
					case "user":
						if h.User == "" {
							h.User = args[0]
						}
					case "port":
						if h.Port == 0 {
							h.Port, _ = strconv.Atoi(args[0])
						}
					case "identityfile":
						if h.IdentityFile == "" {
							h.IdentityFile = args[0]
						}
					}
				}
			}
		}
	}
	walk(path, 0)
	out := make([]Host, 0, len(order))
	for _, a := range order {
		out = append(out, *hosts[a])
	}
	return out
}

// Resolve fills in the effective values via `ssh -G alias` (handles Match, defaults, %-tokens).
// Falls back to the parsed values if ssh -G fails.
func Resolve(h Host, configPath string) Host {
	args := []string{"-G"}
	if configPath != "" && configPath != DefaultPath() {
		args = append(args, "-F", configPath)
	}
	out, err := exec.Command("ssh", append(args, h.Alias)...).Output()
	if err != nil {
		return h
	}
	r := h
	r.IdentityFile = ""
	home, _ := os.UserHomeDir()
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch k {
		case "hostname":
			r.HostName = v
		case "user":
			r.User = v
		case "port":
			r.Port, _ = strconv.Atoi(v)
		case "identityfile":
			// ssh -G lists the default candidates too; keep the first one that exists
			p := v
			if strings.HasPrefix(p, "~/") {
				p = filepath.Join(home, p[2:])
			}
			if r.IdentityFile == "" {
				if _, err := os.Stat(p); err == nil {
					r.IdentityFile = v
				}
			}
		}
	}
	if r.IdentityFile == "" {
		r.IdentityFile = h.IdentityFile
	}
	return r
}
