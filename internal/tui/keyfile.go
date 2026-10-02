package tui

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Key file helpers for the connection form: detecting private keys, inline path completion and the
// validation hint. Only the first bytes of a file are read (the header and, for OpenSSH keys, the public
// part); key material is never shown.

// keyHeadSize is how much of a file is read to classify it.
const keyHeadSize = 4096

// keyInfo describes a file as far as the form cares.
type keyInfo struct {
	Private   bool   // has an OpenSSH or PEM "PRIVATE KEY" header
	Public    bool   // looks like an OpenSSH public key (or ends in .pub)
	Encrypted bool   // the private key needs a passphrase
	Type      string // ed25519, rsa, ecdsa, … ("" if unknown)
	Comment   string // from the matching .pub
}

// sshKey is a private key found in the ssh dir.
type sshKey struct {
	Path    string // absolute
	Display string // with ~
	keyInfo
}

// readHead reads at most keyHeadSize bytes of a regular file.
func readHead(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	buf := make([]byte, keyHeadSize)
	n, err := io.ReadFull(fh, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// classifyKey inspects the head of a file.
func classifyKey(head []byte) keyInfo {
	var ki keyInfo
	text := string(head)
	trim := strings.TrimLeft(text, " \t\r\n")
	if strings.HasPrefix(trim, "-----BEGIN ") {
		first, _, _ := strings.Cut(trim, "\n")
		first = strings.TrimSpace(first)
		if !strings.HasSuffix(first, "PRIVATE KEY-----") {
			return ki
		}
		ki.Private = true
		label := strings.TrimSuffix(strings.TrimPrefix(first, "-----BEGIN "), "PRIVATE KEY-----")
		switch strings.TrimSpace(label) {
		case "OPENSSH":
			ki.Type, ki.Encrypted = parseOpenSSHHead(trim)
		case "RSA":
			ki.Type = "rsa"
		case "EC":
			ki.Type = "ecdsa"
		case "DSA":
			ki.Type = "dsa"
		case "ENCRYPTED":
			ki.Encrypted = true
		}
		if strings.Contains(text, "Proc-Type: 4,ENCRYPTED") {
			ki.Encrypted = true
		}
		return ki
	}
	if fields := strings.Fields(trim); len(fields) >= 2 && isPubKeyType(fields[0]) {
		ki.Public = true
		ki.Type = shortKeyType(fields[0])
	}
	return ki
}

// parseOpenSSHHead decodes the beginning of an "openssh-key-v1" body: the cipher (none = not encrypted) and
// the key type from the embedded public key.
func parseOpenSSHHead(pem string) (typ string, encrypted bool) {
	var b64 strings.Builder
	for i, line := range strings.Split(pem, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue
		}
		if strings.HasPrefix(line, "-----END") {
			break
		}
		b64.WriteString(line)
	}
	s := b64.String()
	s = s[:len(s)/4*4] // the head may cut the body
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// a trailing padded group in the middle cannot happen; anything else is not a key we understand
		return "", false
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return "", false
	}
	r := raw[len(magic):]
	next := func() ([]byte, bool) {
		if len(r) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(r)
		if uint64(n) > uint64(len(r)-4) {
			return nil, false
		}
		v := r[4 : 4+n]
		r = r[4+n:]
		return v, true
	}
	cipher, ok := next()
	if !ok {
		return "", false
	}
	encrypted = string(cipher) != "none"
	if _, ok = next(); !ok { // kdf name
		return "", encrypted
	}
	if _, ok = next(); !ok { // kdf options
		return "", encrypted
	}
	if len(r) < 4 {
		return "", encrypted
	}
	r = r[4:] // number of keys
	pub, ok := next()
	if !ok || len(pub) < 4 {
		return "", encrypted
	}
	r = pub
	if t, ok := next(); ok {
		typ = shortKeyType(string(t))
	}
	return typ, encrypted
}

func isPubKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-sha2-") || strings.HasPrefix(t, "sk-")
}

// shortKeyType maps an ssh key type name to a short label.
func shortKeyType(t string) string {
	switch {
	case t == "ssh-ed25519":
		return "ed25519"
	case t == "ssh-rsa":
		return "rsa"
	case t == "ssh-dss":
		return "dsa"
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		return "ecdsa"
	case strings.HasPrefix(t, "sk-ssh-ed25519"):
		return "ed25519-sk"
	case strings.HasPrefix(t, "sk-ecdsa"):
		return "ecdsa-sk"
	}
	return oneLine(t)
}

// readPub reads type and comment from path.pub (if present).
func readPub(path string) (typ, comment string, ok bool) {
	head, err := readHead(path + ".pub")
	if err != nil {
		return "", "", false
	}
	line, _, _ := strings.Cut(string(head), "\n")
	f := strings.Fields(line)
	if len(f) < 2 || !isPubKeyType(f[0]) {
		return "", "", false
	}
	if len(f) > 2 {
		comment = oneLine(strings.Join(f[2:], " "))
	}
	return shortKeyType(f[0]), comment, true
}

// inspectKey classifies the file at path (and pairs it with its .pub).
func inspectKey(path string) (keyInfo, error) {
	head, err := readHead(path)
	if err != nil {
		return keyInfo{}, err
	}
	ki := classifyKey(head)
	if ki.Private {
		if t, c, ok := readPub(path); ok {
			if t != "" {
				ki.Type = t
			}
			ki.Comment = c
		}
	}
	return ki, nil
}

// skipKeyName reports files in the ssh dir that are never private keys.
func skipKeyName(name string) bool {
	return strings.HasSuffix(name, ".pub") || strings.HasPrefix(name, "known_hosts") || name == "config" ||
		strings.HasPrefix(name, "authorized_keys") || strings.HasPrefix(name, ".")
}

// scanKeys lists the private keys directly in dir (not recursive), sorted by name.
func scanKeys(dir, home string) []sshKey {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []sshKey
	for _, e := range entries {
		if len(out) >= 100 {
			break
		}
		name := e.Name()
		if skipKeyName(name) {
			continue
		}
		p := filepath.Join(dir, name)
		st, err := os.Stat(p) // follows symlinks; sockets, fifos and dirs are skipped
		if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
			continue
		}
		ki, err := inspectKey(p)
		if err != nil || !ki.Private {
			continue
		}
		out = append(out, sshKey{Path: p, Display: tildeHome(p, home), keyInfo: ki})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Display < out[j].Display })
	return out
}

// tildeHome shows p under home with ~.
func tildeHome(p, home string) string {
	if home == "" || home == "/" {
		return p
	}
	home = filepath.Clean(home)
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

// expandHome resolves a leading ~ or ~/.
func expandHome(p, home string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		out := filepath.Join(home, p[2:])
		if strings.HasSuffix(p, "/") && out != "/" {
			out += "/"
		}
		return out
	}
	return p
}

// filterKeys keeps the keys whose display path or comment matches q: substring matches first, then
// subsequence (fuzzy) matches. An empty query keeps all.
func filterKeys(keys []sshKey, q, home string) []sshKey {
	q = strings.TrimSpace(q)
	if q == "" {
		return keys
	}
	q = strings.ToLower(tildeHome(q, home))
	var sub, fuzzy []sshKey
	for _, k := range keys {
		hay := []string{strings.ToLower(k.Display), strings.ToLower(k.Comment)}
		switch {
		case strings.Contains(hay[0], q) || strings.Contains(hay[1], q):
			sub = append(sub, k)
		case subsequence(hay[0], q) || subsequence(hay[1], q):
			fuzzy = append(fuzzy, k)
		}
	}
	return append(sub, fuzzy...)
}

// completePath returns the text to append to input for the best path completion ("" if none).
// ~ is expanded, directories complete with a trailing /. Hidden entries are only offered when the typed
// name starts with a dot, and .pub files only when nothing else matches. Private keys are preferred, then
// directories, then other files (each alphabetically).
func completePath(input, home string) string {
	if input == "" || strings.ContainsAny(input, "\n\r\x00") {
		return ""
	}
	if input == "~" {
		return "/"
	}
	full := expandHome(input, home)
	dir, base := filepath.Split(full)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	type cand struct {
		name string
		rank int
	}
	var cands, pubs []cand
	exactFile := false
	for i, e := range entries {
		if i > 2000 {
			break
		}
		name := e.Name()
		if name == base && !e.IsDir() {
			exactFile = true
		}
		if name == base || !strings.HasPrefix(name, base) || (strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		isDir := e.IsDir()
		if e.Type()&fs.ModeSymlink != 0 {
			if st, err := os.Stat(filepath.Join(dir, name)); err == nil {
				isDir = st.IsDir()
			}
		}
		c := cand{name: name, rank: 2}
		switch {
		case isDir:
			c.name += "/"
			c.rank = 1
		case strings.HasSuffix(name, ".pub"):
			pubs = append(pubs, c)
			continue
		case len(cands) < 200:
			if ki, err := inspectKey(filepath.Join(dir, name)); err == nil && ki.Private {
				c.rank = 0
			}
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 && !exactFile {
		cands = pubs // id_rsa.p → id_rsa.pub, but a complete id_rsa is not extended to the .pub
	}
	if len(cands) == 0 {
		// an exact directory name without the slash
		if base != "" {
			if st, err := os.Stat(full); err == nil && st.IsDir() && !strings.HasSuffix(input, "/") {
				return "/"
			}
		}
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].rank != cands[j].rank {
			return cands[i].rank < cands[j].rank
		}
		return cands[i].name < cands[j].name
	})
	return cands[0].name[len(base):]
}

// keyCheck is the validation hint for the key file field.
type keyCheck struct {
	level int // 0 neutral, 1 ok, 2 warning, 3 error
	text  string
}

const (
	checkNeutral = iota
	checkOK
	checkWarn
	checkBad
)

// checkKeyFile validates the key file field. hasPassphrase: a passphrase is stored or typed.
func checkKeyFile(value, home string, hasPassphrase bool) keyCheck {
	value = strings.TrimSpace(value)
	if value == "" {
		return keyCheck{checkNeutral, "empty: ssh defaults / agent (ssh-agent, ~/.ssh/id_*)"}
	}
	p := expandHome(value, home)
	st, err := os.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return keyCheck{checkBad, "file not found"}
	case errors.Is(err, fs.ErrPermission):
		return keyCheck{checkBad, "cannot read: permission denied"}
	case err != nil:
		return keyCheck{checkBad, "cannot read the file"}
	case st.IsDir():
		return keyCheck{checkBad, "this is a directory — pick a key file"}
	case !st.Mode().IsRegular():
		return keyCheck{checkBad, "not a regular file"}
	}
	if strings.HasSuffix(p, ".pub") {
		return keyCheck{checkBad, "this is a public key (.pub) — pick the private key"}
	}
	ki, err := inspectKey(p)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return keyCheck{checkBad, "cannot read: permission denied"}
		}
		return keyCheck{checkBad, "cannot read the file"}
	}
	if ki.Public {
		return keyCheck{checkBad, "this is a public key (.pub) — pick the private key"}
	}
	if !ki.Private {
		return keyCheck{checkBad, "not a private key (no PRIVATE KEY header)"}
	}
	if st.Mode().Perm()&0o077 != 0 {
		return keyCheck{checkWarn, "permissions too open (chmod 600)"}
	}
	if ki.Encrypted && !hasPassphrase {
		return keyCheck{checkWarn, "encrypted — enter the passphrase below"}
	}
	var parts []string
	if ki.Type != "" {
		parts = append(parts, ki.Type)
	}
	if ki.Comment != "" {
		parts = append(parts, ki.Comment)
	}
	if ki.Encrypted {
		parts = append(parts, "passphrase")
	}
	t := "valid private key"
	if len(parts) > 0 {
		t += " (" + strings.Join(parts, " · ") + ")"
	}
	return keyCheck{checkOK, t}
}

// render shows the hint with its icon and color.
func (c keyCheck) render() string {
	switch c.level {
	case checkOK:
		return goodStyle.Render("✓ " + c.text)
	case checkWarn:
		return warnStyle.Render("⚠ " + c.text)
	case checkBad:
		return badStyle.Render("✗ " + c.text)
	}
	return dimStyle.Render(c.text)
}
