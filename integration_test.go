package main

// Integration test against a throwaway sshd container (alpine + openssh) with a password user and a key user.
// Runs the real `tussh mcp` binary with real ssh. Skipped when docker or ssh is unavailable or TUSSH_INTEGRATION=0.
// The container, the generated key and all temp dirs are removed afterwards.

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
	"github.com/baeroe/tussh/internal/secrets"
	"github.com/baeroe/tussh/internal/sshrun"
)

const (
	sshdImage  = "alpine:3.20"
	pwPassword = "pw-Secret-4711"
)

const sshdScript = `set -e
apk add --no-cache openssh >/dev/null
ssh-keygen -A >/dev/null
adduser -D pwuser; echo "pwuser:$PW" | chpasswd >/dev/null 2>&1
adduser -D keyuser; echo "keyuser:$(head -c 18 /dev/urandom | base64)" | chpasswd >/dev/null 2>&1
mkdir -p /home/keyuser/.ssh; echo "$PUBKEY" > /home/keyuser/.ssh/authorized_keys
chown -R keyuser /home/keyuser/.ssh; chmod 700 /home/keyuser/.ssh; chmod 600 /home/keyuser/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no -o AllowTcpForwarding=yes -o UsePAM=no`

func dockerAvailable() bool {
	if os.Getenv("TUSSH_INTEGRATION") == "0" {
		return false
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return false
	}
	return exec.Command("docker", "info").Run() == nil
}

func TestIntegrationSSHD(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker/ssh not available (or TUSSH_INTEGRATION=0)")
	}
	sb := newSandbox(t)
	// real ssh instead of the fake one
	var env []string
	for _, e := range sb.env {
		if !strings.HasPrefix(e, "TUSSH_SSH_BIN=") {
			env = append(env, e)
		}
	}
	sshCfg := filepath.Join(sb.dir, "ssh_config")
	os.WriteFile(sshCfg, []byte("Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n"), 0o600)
	env = append(env, "TUSSH_SSH_CONFIG="+sshCfg)
	t.Setenv("TUSSH_SSH_CONFIG", sshCfg)
	t.Setenv("TUSSH_SSH_BIN", "")
	t.Setenv("TUSSH_SELF", tusshBin) // askpass for in-process sshrun calls (tunnel test)

	key := filepath.Join(sb.dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tussh-test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	out, err := exec.Command("docker", "run", "-d", "--rm", "--label", "tussh-test=1", "-p", "127.0.0.1::22",
		"-e", "PUBKEY="+strings.TrimSpace(string(pub)), "-e", "PW="+pwPassword, sshdImage, "sh", "-c", sshdScript).Output()
	if err != nil {
		t.Fatalf("docker run: %v", err)
	}
	container := strings.TrimSpace(string(out))
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", container).Run() })
	pout, err := exec.Command("docker", "port", container, "22").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	line := strings.Split(strings.TrimSpace(string(pout)), "\n")[0]
	port, _ := strconv.Atoi(line[strings.LastIndex(line, ":")+1:])

	pwConn := config.Connection{ID: "aaaa0001", Name: "pw-ro", Host: "127.0.0.1", Port: port, User: "pwuser",
		Auth: config.AuthPassword, HasPassword: true, AccessLevel: config.LevelReadOnly}
	keyConn := config.Connection{ID: "aaaa0002", Name: "key-trusted", Host: "127.0.0.1", Port: port, User: "keyuser",
		Auth: config.AuthKey, KeyPath: key, AccessLevel: config.LevelTrusted,
		Tunnels: []config.Tunnel{{Name: "sshd", Local: freePort(t), RemoteHost: "127.0.0.1", RemotePort: 22}}}
	eachConn := keyConn
	eachConn.ID, eachConn.Name, eachConn.AccessLevel, eachConn.Tunnels = "aaaa0003", "key-each", config.LevelApproveEach, nil
	sb.addConnections(t, pwConn, keyConn, eachConn)
	if err := secrets.Open().Set(secrets.Account(pwConn.ID, secrets.KindPassword), pwPassword); err != nil {
		t.Fatal(err)
	}

	// wait for apk + sshd
	deadline := time.Now().Add(120 * time.Second)
	for {
		cmd := exec.Command("ssh", append(sshrun.Args(keyConn, sshrun.ModeAgent), "true")...)
		cmd.Env = env
		if cmd.Run() == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
			t.Fatalf("sshd did not come up: %s", logs)
		}
		time.Sleep(time.Second)
	}

	c := startMCP(t, env)
	c.init()
	q := approval.Open()

	t.Run("password auth via askpass, read-only auto", func(t *testing.T) {
		isErr, text, sc := c.call("run_command", map[string]any{"connection": "pw-ro", "command": "whoami"})
		if isErr || sc["decision"] != "auto" || sc["stdout"] != "pwuser\n" {
			t.Fatalf("%s", text)
		}
		isErr, text, sc = c.call("run_command", map[string]any{"connection": "pw-ro", "command": "cat /etc/os-release"})
		if isErr || !strings.Contains(sc["stdout"].(string), "Alpine") {
			t.Fatalf("%s", text)
		}
		// read-only arguments are passed literally: no remote globbing
		_, _, sc = c.call("run_command", map[string]any{"connection": "pw-ro", "command": "ls /home/*"})
		if sc["exit_code"].(float64) == 0 {
			t.Fatalf("glob was expanded: %v", sc)
		}
	})

	t.Run("key auth, trusted auto", func(t *testing.T) {
		isErr, text, sc := c.call("run_command", map[string]any{"connection": "key-trusted", "command": "whoami && echo hi | tr a-z A-Z"})
		if isErr || sc["decision"] != "auto" || sc["stdout"] != "keyuser\nHI\n" {
			t.Fatalf("%s", text)
		}
		_, _, sc = c.call("run_command", map[string]any{"connection": "key-trusted", "command": "exit 7"})
		if sc["exit_code"].(float64) != 7 {
			t.Fatalf("exit code: %v", sc)
		}
	})

	t.Run("approval required: approve and deny", func(t *testing.T) {
		ch := c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{
			"connection": "pw-ro", "command": "touch /tmp/approved && echo done", "justification": "integration"}})
		r := awaitPending(t, "touch /tmp/approved && echo done")
		q.Resolve(r.ID, approval.Approved, "test", "")
		isErr, text, sc := toolResult(t, c.wait(ch, 60*time.Second))
		if isErr || sc["decision"] != "approved" || sc["stdout"] != "done\n" {
			t.Fatalf("approve: %s", text)
		}
		ch = c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "pw-ro", "command": "touch /tmp/denied"}})
		r = awaitPending(t, "touch /tmp/denied")
		q.Resolve(r.ID, approval.Denied, "test", "")
		if isErr, text, _ := toolResult(t, c.wait(ch, 60*time.Second)); !isErr || !strings.Contains(text, "denied") {
			t.Fatalf("deny: %s", text)
		}
		_, _, sc = c.call("run_command", map[string]any{"connection": "key-trusted", "command": "test -e /tmp/approved && echo yes; test -e /tmp/denied && echo leaked || echo no"})
		if sc["stdout"] != "yes\nno\n" {
			t.Fatalf("effects: %v", sc["stdout"])
		}
	})

	t.Run("sensitive command needs approval on trusted", func(t *testing.T) {
		ch := c.send("tools/call", map[string]any{"name": "run_command", "arguments": map[string]any{"connection": "key-trusted", "command": "rm -f /tmp/approved"}})
		r := awaitPending(t, "rm -f /tmp/approved")
		if !strings.Contains(strings.Join(r.Reasons, " "), "delete") {
			t.Fatalf("reasons: %v", r.Reasons)
		}
		q.Resolve(r.ID, approval.Denied, "test", "")
		if isErr, _, _ := toolResult(t, c.wait(ch, 60*time.Second)); !isErr {
			t.Fatal("sensitive command ran")
		}
		_, _, sc := c.call("run_command", map[string]any{"connection": "key-trusted", "command": "ls /tmp/approved"})
		if sc["exit_code"].(float64) != 0 {
			t.Fatal("file was deleted although denied")
		}
	})

	t.Run("remote command timeout", func(t *testing.T) {
		_, text, sc := c.call("run_command", map[string]any{"connection": "key-trusted", "command": "sleep 30", "timeout": 2})
		if sc["timed_out"] != true {
			t.Fatalf("%s", text)
		}
	})

	t.Run("approval timeout auto-deny", func(t *testing.T) {
		c2 := startMCP(t, append(append([]string(nil), env...), "TUSSH_APPROVAL_TIMEOUT=2"))
		c2.init()
		isErr, text, _ := c2.call("run_command", map[string]any{"connection": "key-each", "command": "uptime"})
		if !isErr || !strings.Contains(text, "denied automatically") {
			t.Fatalf("%s", text)
		}
	})

	t.Run("tunnel", func(t *testing.T) {
		tn := keyConn.Tunnels[0]
		st, err := sshrun.StartTunnel(keyConn, tn, 20*time.Second)
		if err != nil || !st.Running {
			t.Fatalf("start: %v", err)
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(tn.Local), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 8)
		n, _ := conn.Read(buf)
		conn.Close()
		if !strings.HasPrefix(string(buf[:n]), "SSH-2.0") {
			t.Fatalf("banner %q", buf[:n])
		}
		sshrun.StopTunnel(keyConn, tn)
		if sshrun.Status(keyConn, tn).Running {
			t.Fatal("still running")
		}
	})

	entries, _ := audit.Read(0)
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Decision]++
	}
	if counts[audit.Auto] < 5 || counts[audit.Approved] != 1 || counts[audit.Denied] != 2 || counts[audit.Timeout] != 1 {
		t.Fatalf("audit counts: %v", counts)
	}
	auditData, _ := os.ReadFile(audit.File())
	if strings.Contains(string(auditData), pwPassword) {
		t.Fatal("password in audit log")
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
