package notify

import "testing"

func TestAppleScriptString(t *testing.T) {
	if got := appleScriptString(`rm "x" \ y`); got != `"rm \"x\" \\ y"` {
		t.Fatal(got)
	}
	if short("a\n  b", 10) != "a b" {
		t.Fatal(short("a\n  b", 10))
	}
}

func TestHerdrBinMissing(t *testing.T) {
	t.Setenv("HERDR_BIN_PATH", "/nonexistent/herdr")
	t.Setenv("PATH", "/nonexistent")
	t.Setenv("HOME", t.TempDir())
	if HerdrBin() != "" {
		t.Fatal("expected no herdr")
	}
	InvokeHerdr() // must not fail or block
}
