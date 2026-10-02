package classify

import (
	"errors"
	"regexp"
	"strings"
)

// ShellSplit splits a command line like Python's shlex.split (POSIX mode, no comments):
// whitespace separates words, single quotes are literal, double quotes allow \" and \\ escapes,
// a backslash outside quotes escapes the next character.
func ShellSplit(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	const (
		plain = iota
		single
		double
	)
	state := plain
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch state {
		case plain:
			switch {
			case c == ' ' || c == '\t' || c == '\n' || c == '\r':
				if inWord {
					words = append(words, cur.String())
					cur.Reset()
					inWord = false
				}
			case c == '\'':
				state, inWord = single, true
			case c == '"':
				state, inWord = double, true
			case c == '\\':
				if i+1 >= len(rs) {
					return nil, errors.New("no escaped character")
				}
				i++
				cur.WriteRune(rs[i])
				inWord = true
			default:
				cur.WriteRune(c)
				inWord = true
			}
		case single:
			if c == '\'' {
				state = plain
			} else {
				cur.WriteRune(c)
			}
		case double:
			switch {
			case c == '"':
				state = plain
			case c == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\'):
				i++
				cur.WriteRune(rs[i])
			default:
				cur.WriteRune(c)
			}
		}
	}
	if state != plain {
		return nil, errors.New("no closing quotation")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

var safeWordRE = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// Quote quotes a word for a POSIX shell like Python's shlex.quote.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if safeWordRE.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// QuoteArgv joins words, each quoted.
func QuoteArgv(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}

// segment is one simple command of a shell line (split at ; && || | & newline ( ) $( ` { }).
type segment struct {
	words     []string // quotes removed
	redirects []string // targets of > and >> redirections (not 2>&1 style fd dups)
}

// segments lexes a command line leniently for rule matching. It never fails: unbalanced quotes simply
// run to the end of the line (the caller treats unparseable lines as "unsure" separately).
func segments(s string) []segment {
	var segs []segment
	var cur segment
	var word strings.Builder
	inWord := false
	pendingRedirect := false
	flushWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		if pendingRedirect {
			cur.redirects = append(cur.redirects, w)
			pendingRedirect = false
			return
		}
		cur.words = append(cur.words, w)
	}
	flushSeg := func() {
		flushWord()
		pendingRedirect = false
		if len(cur.words) > 0 || len(cur.redirects) > 0 {
			segs = append(segs, cur)
		}
		cur = segment{}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case ' ', '\t':
			flushWord()
		case '\n', '\r', ';', '|', '&', '(', ')', '`', '{', '}':
			// "&>" and ">&" are redirections, handled at '>'.
			if c == '&' && i+1 < len(rs) && rs[i+1] == '>' {
				flushWord()
				continue
			}
			if c == '{' || c == '}' {
				// only treat braces as grouping when they stand alone
				if inWord || (i+1 < len(rs) && rs[i+1] != ' ' && rs[i+1] != '\t' && rs[i+1] != '\n' && c == '{') {
					word.WriteRune(c)
					inWord = true
					continue
				}
			}
			flushSeg()
		case '$':
			if i+1 < len(rs) && rs[i+1] == '(' {
				flushSeg()
				i++
				continue
			}
			word.WriteRune(c)
			inWord = true
		case '<':
			flushWord()
			if i+1 < len(rs) && rs[i+1] == '(' { // process substitution
				flushSeg()
				i++
			}
		case '>':
			// strip an fd number directly before (2>file): it was collected into the current word
			if inWord {
				w := word.String()
				if strings.Trim(w, "0123456789") == "" {
					word.Reset()
					inWord = false
				} else {
					flushWord()
				}
			}
			j := i + 1
			if j < len(rs) && rs[j] == '>' {
				j++
			}
			if j < len(rs) && rs[j] == '&' { // >&2 or >&file
				j++
				k := j
				for k < len(rs) && rs[k] >= '0' && rs[k] <= '9' {
					k++
				}
				if k > j || (k < len(rs) && rs[k] == '-') { // fd duplication, not a file
					if k < len(rs) && rs[k] == '-' {
						k++
					}
					i = k - 1
					continue
				}
			}
			if j < len(rs) && rs[j] == '(' { // >(cmd) process substitution
				i = j
				flushSeg()
				continue
			}
			i = j - 1
			pendingRedirect = true
		case '\'':
			inWord = true
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				word.WriteRune(rs[i])
			}
		case '"':
			inWord = true
			for i++; i < len(rs) && rs[i] != '"'; i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
				}
				word.WriteRune(rs[i])
			}
		case '\\':
			if i+1 < len(rs) {
				i++
				if rs[i] == '\n' {
					continue
				}
				word.WriteRune(rs[i])
				inWord = true
			}
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	flushSeg()
	return segs
}
