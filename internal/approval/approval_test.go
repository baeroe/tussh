package approval

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newQueue(t *testing.T) *Queue {
	t.Setenv("TUSSH_STATE_DIR", t.TempDir())
	return Open()
}

func TestSubmitPendingResolve(t *testing.T) {
	q := newQueue(t)
	r := &Request{Connection: "web", Command: "rm x", Reasons: []string{"delete"}, Expires: time.Now().Add(time.Minute)}
	if err := q.Submit(r); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(q.Dir, r.ID+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("request file mode: %v %v", info.Mode(), err)
	}
	p := q.Pending()
	if len(p) != 1 || p[0].ID != r.ID || p[0].Command != "rm x" {
		t.Fatalf("pending: %+v", p)
	}
	if err := q.Resolve(r.ID, Approved, "test", ""); err != nil {
		t.Fatal(err)
	}
	if len(q.Pending()) != 0 {
		t.Fatal("decided request still pending")
	}
	if err := q.Resolve(r.ID, Denied, "test", ""); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("second resolve: %v", err)
	}
	d, err := q.Decision(r.ID)
	if err != nil || d.Decision != Approved {
		t.Fatalf("decision %+v %v", d, err)
	}
	if err := q.Resolve("../../etc/passwd", Approved, "x", ""); !errors.Is(err, ErrUnknown) {
		t.Fatalf("path traversal id: %v", err)
	}
	if err := q.Resolve("abcdef", "maybe", "x", ""); err == nil {
		t.Fatal("invalid decision accepted")
	}
}

func TestConcurrentResolveExactlyOneWins(t *testing.T) {
	q := newQueue(t)
	for round := 0; round < 20; round++ {
		r := &Request{Command: "x"}
		if err := q.Submit(r); err != nil {
			t.Fatal(err)
		}
		var wins int32
		var wg sync.WaitGroup
		decisions := []string{Approved, Denied, Timeout}
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				err := q.Resolve(r.ID, decisions[i%3], "g", "")
				if err == nil {
					atomic.AddInt32(&wins, 1)
				} else if !errors.Is(err, ErrAlreadyDecided) {
					t.Errorf("unexpected error %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("round %d: %d winners", round, wins)
		}
		d, err := q.Decision(r.ID)
		if err != nil || d.Decision == "" {
			t.Fatalf("decision unreadable: %v", err)
		}
	}
}

func TestWaitApproved(t *testing.T) {
	q := newQueue(t)
	r := &Request{Command: "x"}
	q.Submit(r)
	go func() {
		time.Sleep(100 * time.Millisecond)
		q.Resolve(r.ID, Approved, "tui", "")
	}()
	d, err := q.Wait(r.ID, 5*time.Second, 20*time.Millisecond, nil)
	if err != nil || d.Decision != Approved || d.By != "tui" {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := os.Stat(filepath.Join(q.Dir, r.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("request file not cleaned up")
	}
}

func TestWaitTimeout(t *testing.T) {
	q := newQueue(t)
	r := &Request{Command: "x"}
	q.Submit(r)
	start := time.Now()
	d, err := q.Wait(r.ID, 300*time.Millisecond, 20*time.Millisecond, nil)
	if err != nil || d.Decision != Timeout {
		t.Fatalf("%+v %v", d, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout took too long")
	}
	// a late human decision is rejected
	if err := q.Resolve(r.ID, Approved, "tui", ""); err == nil {
		t.Fatal("late approval accepted")
	}
}

func TestWaitCancel(t *testing.T) {
	q := newQueue(t)
	r := &Request{Command: "x"}
	q.Submit(r)
	cancel := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(cancel) }()
	d, err := q.Wait(r.ID, 10*time.Second, 20*time.Millisecond, cancel)
	if err != nil || d.Decision != Denied {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestAtomicWritesNeverPartial(t *testing.T) {
	// Readers polling Pending() while requests are written must never see a partial JSON file.
	q := newQueue(t)
	stop := make(chan struct{})
	var bad int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, _ := os.ReadDir(q.Dir)
			for _, e := range entries {
				if filepath.Ext(e.Name()) != ".json" || e.Name()[0] == '.' {
					continue
				}
				data, err := os.ReadFile(filepath.Join(q.Dir, e.Name()))
				if err != nil {
					continue // removed meanwhile
				}
				var v map[string]any
				if json.Unmarshal(data, &v) != nil {
					atomic.AddInt32(&bad, 1)
				}
			}
		}
	}()
	big := make([]byte, 200000)
	for i := range big {
		big[i] = 'a'
	}
	for i := 0; i < 50; i++ {
		r := &Request{Command: string(big)}
		q.Submit(r)
		q.Resolve(r.ID, Denied, "t", "")
	}
	close(stop)
	wg.Wait()
	if bad > 0 {
		t.Fatalf("%d partial reads", bad)
	}
}

func TestPendingDropsDeadRequester(t *testing.T) {
	q := newQueue(t)
	r := &Request{Command: "x", PID: 999999}
	q.Submit(r)
	if len(q.Pending()) != 0 {
		t.Fatal("request of a dead process is still pending")
	}
	if _, err := os.Stat(filepath.Join(q.Dir, r.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("stale request not removed")
	}
}

func TestPresence(t *testing.T) {
	t.Setenv("TUSSH_STATE_DIR", t.TempDir())
	if TUIOpen() {
		t.Fatal("no TUI yet")
	}
	Heartbeat()
	if !TUIOpen() {
		t.Fatal("heartbeat not seen")
	}
	ClearHeartbeat()
	if TUIOpen() {
		t.Fatal("cleared heartbeat still seen")
	}
}
