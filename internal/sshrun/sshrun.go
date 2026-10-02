// Package sshrun builds ssh command lines for connections, runs agent commands with timeouts and output caps,
// and implements the askpass side of password / passphrase authentication.
package sshrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/baeroe/tussh/internal/config"
)

// Limits for agent runs.
const (
	DefaultTimeout = 30 * time.Second
	MaxTimeout     = 600 * time.Second
	ConnectTimeout = 10
	MaxOutput      = 20000 // bytes kept per stream (head + tail)
)

// SSHBin is the ssh binary (TUSSH_SSH_BIN overrides, used by tests).
func SSHBin() string {
	if b := os.Getenv("TUSSH_SSH_BIN"); b != "" {
		return b
	}
	return "ssh"
}

// Self is the absolute path of the running tussh binary (used as SSH_ASKPASS).
func Self() string {
	if p := os.Getenv("TUSSH_SELF"); p != "" {
		return p
	}
	p, err := os.Executable()
	if err != nil {
		return "tussh"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// Mode selects the flavour of the ssh command line.
type Mode int

const (
	ModeAgent       Mode = iota // non-interactive agent run: -T, hardened options
	ModeInteractive             // human session in the terminal
	ModeTunnel                  // ssh -N -L
)

// needsAskpass reports whether a secret from the keyring is used for this connection.
func needsAskpass(c config.Connection) bool {
	if c.Auth == config.AuthPassword {
		return c.HasPassword
	}
	return c.HasPassphrase
}

// Args returns the ssh argv (without the binary) up to and including the host.
func Args(c config.Connection, mode Mode) []string {
	var a []string
	if cfg := os.Getenv("TUSSH_SSH_CONFIG"); cfg != "" {
		a = append(a, "-F", cfg)
	}
	a = append(a, "-o", fmt.Sprintf("ConnectTimeout=%d", ConnectTimeout))
	if mode != ModeInteractive {
		// agents and tunnels: never reuse or create a user's multiplexed connection, no forwarding of
		// agent/X11, no local commands
		a = append(a, "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ForwardAgent=no",
			"-o", "ForwardX11=no", "-o", "PermitLocalCommand=no")
		if needsAskpass(c) {
			a = append(a, "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1")
		} else {
			a = append(a, "-o", "BatchMode=yes")
		}
	}
	if mode == ModeAgent {
		a = append(a, "-o", "ClearAllForwardings=yes", "-T")
	}
	a = append(a, "-p", strconv.Itoa(c.EffectivePort()))
	if c.User != "" {
		a = append(a, "-l", c.User)
	}
	switch c.Auth {
	case config.AuthPassword:
		a = append(a, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive")
	default:
		if c.KeyPath != "" {
			a = append(a, "-i", c.KeyPathExpanded(), "-o", "IdentitiesOnly=yes")
		}
		if mode != ModeInteractive {
			a = append(a, "-o", "PreferredAuthentications=publickey")
		}
	}
	return append(a, c.Host)
}

// --- askpass tokens -------------------------------------------------------------------

// The parent (TUI or MCP server) writes a one-off token file naming the connection; ssh runs `tussh` as
// SSH_ASKPASS with the token in the environment. The askpass process only answers for a live token,
// so `tussh askpass` cannot be used to read arbitrary secrets without a parent that just created a token.

func tokenDir() string { return filepath.Join(config.StateDir(), "askpass") }

type tokenFile struct {
	ConnID  string    `json:"conn_id"`
	Expires time.Time `json:"expires"`
}

// AskpassEnv holds the environment for one ssh process and removes its token on Close.
type AskpassEnv struct {
	Env   []string
	token string
}

// Close removes the token.
func (a *AskpassEnv) Close() {
	if a != nil && a.token != "" {
		_ = os.Remove(filepath.Join(tokenDir(), a.token))
	}
}

// NewAskpass prepares the askpass environment for a connection. Returns nil if no secret is used.
func NewAskpass(c config.Connection, interactive bool, ttl time.Duration) (*AskpassEnv, error) {
	if !needsAskpass(c) {
		return nil, nil
	}
	tok := config.NewID() + config.NewID()
	data := fmt.Sprintf(`{"conn_id":%q,"expires":%q}`, c.ID, time.Now().Add(ttl).Format(time.RFC3339Nano))
	if err := config.WriteFileAtomic(filepath.Join(tokenDir(), tok), []byte(data), 0o600); err != nil {
		return nil, err
	}
	env := []string{"SSH_ASKPASS=" + Self(), "SSH_ASKPASS_REQUIRE=force", "TUSSH_ASKPASS_MODE=1", "TUSSH_ASKPASS_TOKEN=" + tok}
	if interactive {
		env = append(env, "TUSSH_ASKPASS_INTERACTIVE=1")
	}
	return &AskpassEnv{Env: env, token: tok}, nil
}

// --- agent runs ------------------------------------------------------------------------

// Result of an agent run.
type Result struct {
	ExitCode  *int          `json:"exit_code"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	TimedOut  bool          `json:"timed_out"`
	Truncated bool          `json:"truncated"`
	Duration  time.Duration `json:"-"`
}

// capBuf keeps the first and last MaxOutput/2 bytes.
type capBuf struct {
	head  bytes.Buffer
	tail  []byte
	total int
	limit int
}

func (b *capBuf) Write(p []byte) (int, error) {
	n := len(p)
	b.total += n
	half := b.limit / 2
	if b.head.Len() < half {
		k := half - b.head.Len()
		if k > len(p) {
			k = len(p)
		}
		b.head.Write(p[:k])
		p = p[k:]
	}
	if len(p) > 0 {
		b.tail = append(b.tail, p...)
		if len(b.tail) > half {
			b.tail = append([]byte(nil), b.tail[len(b.tail)-half:]...)
		}
	}
	return n, nil
}

func (b *capBuf) String() (string, bool) {
	if b.total <= b.limit {
		return b.head.String() + string(b.tail), false
	}
	return fmt.Sprintf("%s\n[... %d bytes truncated ...]\n%s", b.head.String(), b.total-b.head.Len()-len(b.tail), string(b.tail)), true
}

// ClampTimeout bounds a requested timeout in seconds.
func ClampTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultTimeout
	}
	d := time.Duration(seconds) * time.Second
	if d > MaxTimeout {
		return MaxTimeout
	}
	return d
}

// Run executes remoteCommand on the connection with stdin closed, killing the whole process group on timeout.
func Run(ctx context.Context, c config.Connection, remoteCommand string, timeout time.Duration) (Result, error) {
	ap, err := NewAskpass(c, false, timeout+time.Minute)
	if err != nil {
		return Result{}, err
	}
	defer ap.Close()
	argv := append(Args(c, ModeAgent), remoteCommand)
	cmd := exec.Command(SSHBin(), argv...)
	cmd.Env = os.Environ()
	if ap != nil {
		cmd.Env = append(cmd.Env, ap.Env...)
	}
	cmd.Stdin = nil // /dev/null
	var out, errb = &capBuf{limit: MaxOutput}, &capBuf{limit: MaxOutput}
	cmd.Stdout, cmd.Stderr = out, errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // own session: no controlling tty, own process group
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("cannot start ssh: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	res := Result{}
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		res.TimedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	case <-ctx.Done():
		res.TimedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	}
	res.Duration = time.Since(start)
	var t1, t2 bool
	res.Stdout, t1 = out.String()
	res.Stderr, t2 = errb.String()
	res.Truncated = t1 || t2
	if !res.TimedOut {
		code := 0
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = ee.ExitCode()
		} else if waitErr != nil {
			return res, waitErr
		}
		res.ExitCode = &code
	}
	return res, nil
}

// InteractiveCommand returns an *exec.Cmd for a human session plus a cleanup func (removes the askpass token).
func InteractiveCommand(c config.Connection) (*exec.Cmd, func(), error) {
	ap, err := NewAskpass(c, true, 12*time.Hour)
	if err != nil {
		return nil, func() {}, err
	}
	cmd := exec.Command(SSHBin(), Args(c, ModeInteractive)...)
	cmd.Env = os.Environ()
	if ap != nil {
		cmd.Env = append(cmd.Env, ap.Env...)
	}
	return cmd, ap.Close, nil
}

// CommandLine renders the interactive ssh command for display (no secrets are part of it).
func CommandLine(c config.Connection, mode Mode) string {
	parts := []string{SSHBin()}
	for _, a := range Args(c, mode) {
		if strings.ContainsAny(a, " \t'\"") {
			a = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}
