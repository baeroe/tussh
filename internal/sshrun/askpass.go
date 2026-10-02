package sshrun

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
	"golang.org/x/term"
)

// PromptKind classifies an ssh askpass prompt.
func PromptKind(prompt string) string {
	p := strings.ToLower(prompt)
	switch {
	case strings.Contains(p, "(yes/no") || strings.Contains(p, "fingerprint") || strings.Contains(p, "continue connecting"):
		return "confirm"
	case strings.Contains(p, "passphrase"):
		return secrets.KindPassphrase
	case strings.Contains(p, "password"):
		return secrets.KindPassword
	}
	return "other"
}

// Askpass answers one ssh prompt: the secret for the token's connection on stdout. Host-key confirmations
// and unknown prompts are passed to the terminal in interactive sessions and refused otherwise.
// It never writes the secret anywhere but out.
func Askpass(prompt string, kr secrets.Keyring, out io.Writer) error {
	kind := PromptKind(prompt)
	interactive := os.Getenv("TUSSH_ASKPASS_INTERACTIVE") == "1"
	if kind == "confirm" || kind == "other" {
		if !interactive {
			return fmt.Errorf("tussh askpass: refusing non-interactive prompt %q", strings.TrimSpace(prompt))
		}
		return askTTY(prompt, out, false)
	}
	tok := os.Getenv("TUSSH_ASKPASS_TOKEN")
	if tok == "" || strings.ContainsAny(tok, "/.\\") {
		return errors.New("tussh askpass: no valid token (only usable as SSH_ASKPASS of a tussh-started ssh)")
	}
	data, err := os.ReadFile(filepath.Join(tokenDir(), tok))
	if err != nil {
		return errors.New("tussh askpass: unknown or expired token")
	}
	var t tokenFile
	if err := json.Unmarshal(data, &t); err != nil || time.Now().After(t.Expires) {
		return errors.New("tussh askpass: unknown or expired token")
	}
	if t.Account != "" {
		// connection test of an unsaved form: only the temporary account named by the parent
		if !strings.HasPrefix(t.Account, "test-") || (t.Kind != secrets.KindPassword && t.Kind != secrets.KindPassphrase) {
			return errors.New("tussh askpass: invalid token")
		}
		if kind != t.Kind {
			return fmt.Errorf("tussh askpass: unexpected %s prompt", kind)
		}
		secret, err := kr.Get(t.Account)
		if err != nil {
			return errors.New("tussh askpass: no secret for this test")
		}
		_, err = fmt.Fprintln(out, secret)
		return err
	}
	store, err := config.Load()
	if err != nil {
		return err
	}
	c, ok := store.ByID(t.ConnID)
	if !ok {
		return errors.New("tussh askpass: connection no longer exists")
	}
	// The secret kind follows the connection's auth method, not only the prompt wording.
	want := secrets.KindPassword
	if c.Auth == config.AuthKey {
		want = secrets.KindPassphrase
	}
	if kind != want {
		if interactive {
			return askTTY(prompt, out, kind != "other")
		}
		return fmt.Errorf("tussh askpass: unexpected %s prompt for a %s connection", kind, c.Auth)
	}
	secret, err := kr.Get(secrets.Account(c.ID, want))
	if err != nil {
		if interactive {
			return askTTY(prompt, out, true)
		}
		return fmt.Errorf("tussh askpass: no %s stored for %s", want, c.Name)
	}
	_, err = fmt.Fprintln(out, secret)
	return err
}

// askTTY asks the user on the controlling terminal (interactive sessions only); secret input is not echoed.
func askTTY(prompt string, out io.Writer, secret bool) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("tussh askpass: no terminal to ask")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	if secret {
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	_, err = fmt.Fprintln(out, strings.TrimRight(line, "\r\n"))
	return err
}
