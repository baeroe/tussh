package audit

import (
	"os"
	"sync"
	"testing"
)

func TestAppendReadConcurrent(t *testing.T) {
	t.Setenv("TUSSH_STATE_DIR", t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := i
			Append(Entry{Connection: "c", Command: "cmd", Decision: Auto, ExitCode: &code})
		}(i)
	}
	wg.Wait()
	entries, err := Read(0)
	if err != nil || len(entries) != 50 {
		t.Fatalf("%d entries, %v", len(entries), err)
	}
	if last, _ := Read(5); len(last) != 5 {
		t.Fatal("limit")
	}
	info, _ := os.Stat(File())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}
