package sshrun

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/baeroe/tussh/internal/config"
)

// Tunnels run as background `ssh -N -L` processes tracked by pid files in <state>/tunnels, so they survive the
// TUI and every TUI instance sees the same state. Only the TUI starts tunnels; agents cannot.

// TunnelStatus describes a tunnel's state.
type TunnelStatus struct {
	Conn    config.Connection
	Tunnel  config.Tunnel
	Running bool
	PID     int
}

type pidFile struct {
	PID     int    `json:"pid"`
	Spec    string `json:"spec"`
	Started int64  `json:"started"`
}

func tunnelDir() string { return filepath.Join(config.StateDir(), "tunnels") }

func tunnelFile(c config.Connection, t config.Tunnel, ext string) string {
	return filepath.Join(tunnelDir(), fmt.Sprintf("%s__%s.%s", c.ID, t.Name, ext))
}

// alive reports whether pid runs and is an ssh carrying our forward spec (guards against pid reuse).
func alive(pid int, spec string) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false // cannot verify: never treat (and later kill) an unknown process as ours
	}
	return strings.Contains(string(out), spec)
}

// Status reads a tunnel's pid file; stale files are removed.
func Status(c config.Connection, t config.Tunnel) TunnelStatus {
	st := TunnelStatus{Conn: c, Tunnel: t}
	data, err := os.ReadFile(tunnelFile(c, t, "pid"))
	if err != nil {
		return st
	}
	var pf pidFile
	if json.Unmarshal(data, &pf) != nil {
		return st
	}
	if alive(pf.PID, t.Spec()) {
		st.Running, st.PID = true, pf.PID
		return st
	}
	_ = os.Remove(tunnelFile(c, t, "pid"))
	return st
}

func portOpen(bind string, port int) bool {
	host := bind
	if host == "" || host == "*" || host == "0.0.0.0" || host == "localhost" {
		host = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// StartTunnel starts the forward and waits until the local port accepts connections.
func StartTunnel(c config.Connection, t config.Tunnel, wait time.Duration) (TunnelStatus, error) {
	if st := Status(c, t); st.Running {
		return st, nil
	}
	if portOpen(t.BindAddr(), t.Local) {
		return TunnelStatus{Conn: c, Tunnel: t}, fmt.Errorf("local port %d is already in use", t.Local)
	}
	if err := config.EnsureDir(tunnelDir()); err != nil {
		return TunnelStatus{}, err
	}
	ap, err := NewAskpass(c, false, wait+time.Minute)
	if err != nil {
		return TunnelStatus{}, err
	}
	defer ap.Close() // only needed for authentication, which is over once the port is up
	argv := Args(c, ModeTunnel)
	host := argv[len(argv)-1]
	argv = append(argv[:len(argv)-1], "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-L", t.Spec(), host)
	logPath := tunnelFile(c, t, "log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return TunnelStatus{}, err
	}
	defer logf.Close()
	cmd := exec.Command(SSHBin(), argv...)
	cmd.Env = os.Environ()
	if ap != nil {
		cmd.Env = append(cmd.Env, ap.Env...)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return TunnelStatus{}, err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }() // reap when it ends while we are running
	pf, _ := json.Marshal(pidFile{PID: cmd.Process.Pid, Spec: t.Spec(), Started: time.Now().Unix()})
	if err := config.WriteFileAtomic(tunnelFile(c, t, "pid"), pf, 0o600); err != nil {
		_ = cmd.Process.Kill()
		return TunnelStatus{}, err
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			deadline = time.Now()
			continue
		default:
		}
		if portOpen(t.BindAddr(), t.Local) {
			return Status(c, t), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = os.Remove(tunnelFile(c, t, "pid"))
	detail, _ := os.ReadFile(logPath)
	msg := strings.TrimSpace(string(detail))
	if len(msg) > 500 {
		msg = msg[len(msg)-500:]
	}
	if msg != "" {
		msg = ": " + msg
	}
	return TunnelStatus{Conn: c, Tunnel: t}, fmt.Errorf("tunnel %s did not come up%s", t.Name, msg)
}

// StopTunnel terminates a running tunnel.
func StopTunnel(c config.Connection, t config.Tunnel) TunnelStatus {
	st := Status(c, t)
	if st.Running {
		_ = syscall.Kill(st.PID, syscall.SIGTERM)
		for i := 0; i < 30 && alive(st.PID, t.Spec()); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	_ = os.Remove(tunnelFile(c, t, "pid"))
	return TunnelStatus{Conn: c, Tunnel: t}
}
