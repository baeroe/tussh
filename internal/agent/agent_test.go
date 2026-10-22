package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baeroe/tussh/internal/allow"
	"github.com/baeroe/tussh/internal/approval"
	"github.com/baeroe/tussh/internal/audit"
	"github.com/baeroe/tussh/internal/config"
)

const fakeSSH = "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\nprintf 'REMOTE %s\\n' \"$last\"\nprintf 'warn\\n' >&2\n"

func setup(t *testing.T) (*Service, config.Connection) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TUSSH_CONFIG_DIR", filepath.Join(dir, "config"))
	t.Setenv("TUSSH_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("TUSSH_SSH_CONFIG", "")
	t.Setenv("TUSSH_NO_NOTIFY", "1")
	bin := filepath.Join(dir, "ssh")
	os.WriteFile(bin, []byte(fakeSSH), 0o755)
	t.Setenv("TUSSH_SSH_BIN", bin)
	s, _ := config.Load()
	c, err := s.Upsert(config.Connection{Name: "web", Host: "web.example", Auth: config.AuthKey, AccessLevel: config.LevelApproveEach})
	if err != nil {
		t.Fatal(err)
	}
	s.Save()
	svc := New("test-agent")
	svc.Poll = 10 * time.Millisecond
	svc.Notify = func(approval.Request) {}
	return svc, c
}

// resolveNext decides the next request that shows up in the queue.
func resolveNext(t *testing.T, q *approval.Queue, decision, note string) chan approval.Request {
	ch := make(chan approval.Request, 1)
	go func() {
		for i := 0; i < 500; i++ {
			if p := q.Pending(); len(p) > 0 {
				q.Resolve(p[0].ID, decision, "test", note)
				ch <- p[0]
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(ch)
	}()
	return ch
}

func TestRememberedCommandSkipsApproval(t *testing.T) {
	svc, c := setup(t)
	if _, err := allow.Add(c.ID, c.Name, "systemctl restart nginx", time.Hour, "tui"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "systemctl restart nginx"})
	if err != nil || res.Decision != "approved" || res.Stdout != "REMOTE systemctl restart nginx\n" {
		t.Fatalf("remembered run: %+v %v", res, err)
	}
	entries, _ := audit.Read(1)
	e := entries[0]
	if e.Decision != audit.Approved || e.DecidedBy != "remembered" || e.Stdout != "REMOTE systemctl restart nginx\n" || e.Stderr != "warn\n" {
		t.Fatalf("audit: %+v", e)
	}
	if used := config.LastUsed(); used[c.ID].IsZero() {
		t.Fatal("last used not recorded")
	}
	// a different command (even a prefix or with a suffix) still needs approval
	ch := resolveNext(t, svc.Queue, approval.Denied, "use reload instead")
	_, err = svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "systemctl restart nginx; reboot"})
	if err == nil || !strings.Contains(err.Error(), "use reload instead") {
		t.Fatalf("deny note must reach the agent: %v", err)
	}
	if r := <-ch; r.Command != "systemctl restart nginx; reboot" {
		t.Fatalf("request: %+v", r)
	}
	entries, _ = audit.Read(1)
	if entries[0].Note != "use reload instead" {
		t.Fatalf("note not audited: %+v", entries[0])
	}
}

func TestExpiredRememberedCommandAsksAgain(t *testing.T) {
	svc, c := setup(t)
	allow.Add(c.ID, c.Name, "uptime", -time.Second, "tui")
	ch := resolveNext(t, svc.Queue, approval.Approved, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "uptime"})
	if err != nil || res.Decision != "approved" {
		t.Fatalf("%+v %v", res, err)
	}
	if r, ok := <-ch; !ok || r.Command != "uptime" {
		t.Fatal("an expired entry must not skip the approval")
	}
	entries, _ := audit.Read(1)
	if entries[0].DecidedBy != "test" {
		t.Fatalf("decided by: %q", entries[0].DecidedBy)
	}
}

func TestRememberedEntryIsPerConnection(t *testing.T) {
	svc, _ := setup(t)
	allow.Add("other-id", "web", "uptime", time.Hour, "tui")
	ch := resolveNext(t, svc.Queue, approval.Denied, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "uptime"}); err == nil {
		t.Fatal("entry of another connection id was used")
	}
	<-ch
}

func TestListConnectionsTags(t *testing.T) {
	svc, c := setup(t)
	s, _ := config.Load()
	c.Tags = []string{"prod"}
	s.Upsert(c)
	s.Save()
	l, err := svc.ListConnections()
	if err != nil || len(l) != 1 || strings.Join(l[0].Tags, ",") != "prod" {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestAuditOutputCanBeDisabled(t *testing.T) {
	svc, c := setup(t)
	os.WriteFile(config.SettingsFile(), []byte(`{"disable_audit_output": true}`), 0o600)
	allow.Add(c.ID, c.Name, "uptime", time.Hour, "tui")
	if _, err := svc.RunCommand(context.Background(), RunRequest{Connection: "web", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := audit.Read(1)
	if entries[0].Stdout != "" || entries[0].Stderr != "" {
		t.Fatalf("output logged: %+v", entries[0])
	}
}

func TestPendingApprovalRunsOnlyInWaitApproval(t *testing.T) {
	svc, _ := setup(t)
	svc.WaitSlice = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "systemctl restart nginx"})
	if err != nil || res.Decision != "pending" || res.RequestID == "" || res.ExitCode != nil {
		t.Fatalf("want pending: %+v %v", res, err)
	}
	// approved while no call is waiting: nothing runs until the agent comes back
	if err := svc.Queue.Resolve(res.RequestID, approval.Approved, "test", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if entries, _ := audit.Read(10); len(entries) != 0 {
		t.Fatalf("command ran without a waiting agent: %+v", entries)
	}
	out, err := svc.WaitApproval(ctx, res.RequestID)
	if err != nil || out.Decision != "approved" || out.Stdout != "REMOTE systemctl restart nginx\n" {
		t.Fatalf("wait_approval: %+v %v", out, err)
	}
	if _, err := svc.WaitApproval(ctx, res.RequestID); err == nil || !strings.Contains(err.Error(), "unknown request_id") {
		t.Fatalf("a result must be returned only once: %v", err)
	}
}

func TestPendingApprovalStaysPendingAndDenies(t *testing.T) {
	svc, _ := setup(t)
	svc.WaitSlice = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "uptime"})
	again, err := svc.WaitApproval(ctx, res.RequestID)
	if err != nil || again.Decision != "pending" || again.RequestID != res.RequestID {
		t.Fatalf("still pending: %+v %v", again, err)
	}
	svc.Queue.Resolve(res.RequestID, approval.Denied, "test", "not now")
	if _, err := svc.WaitApproval(ctx, res.RequestID); err == nil || !strings.Contains(err.Error(), "not now") {
		t.Fatalf("deny must reach the agent: %v", err)
	}
	entries, _ := audit.Read(1)
	if entries[0].Decision != audit.Denied || entries[0].ExitCode != nil {
		t.Fatalf("audit: %+v", entries[0])
	}
}

func TestCancelledWaitDeniesRequest(t *testing.T) {
	svc, _ := setup(t)
	svc.WaitSlice = 0
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for len(svc.Queue.Pending()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	if _, err := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "uptime"}); err == nil {
		t.Fatal("a cancelled request must not run")
	}
	entries, _ := audit.Read(1)
	if entries[0].Decision != audit.Denied || entries[0].DecidedBy != "cancelled" {
		t.Fatalf("audit: %+v", entries[0])
	}
}

func TestAbandonedApprovalIsAuditedAsNotRun(t *testing.T) {
	svc, _ := setup(t)
	svc.WaitSlice = 20 * time.Millisecond
	ctx := context.Background()
	res, _ := svc.RunCommand(ctx, RunRequest{Connection: "web", Command: "uptime"})
	svc.Queue.Resolve(res.RequestID, approval.Approved, "test", "")
	svc.mu.Lock()
	p := svc.pending[res.RequestID]
	svc.mu.Unlock()
	<-p.done
	p.decided = time.Now().Add(-abandonAfter - time.Second)
	if _, err := svc.WaitApproval(ctx, "0000"); err == nil {
		t.Fatal("unknown id")
	}
	entries, _ := audit.Read(1)
	if len(entries) != 1 || entries[0].Decision != audit.Approved || entries[0].ExitCode != nil || !strings.Contains(entries[0].Error, "not run") {
		t.Fatalf("audit: %+v", entries)
	}
	if _, err := svc.WaitApproval(ctx, res.RequestID); err == nil {
		t.Fatal("an abandoned request must not run later")
	}
}
