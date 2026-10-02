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
