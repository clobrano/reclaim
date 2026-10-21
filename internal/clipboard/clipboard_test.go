package clipboard

import (
	"bytes"
	"testing"
)

func TestSequence(t *testing.T) {
	if got := Sequence("hi", Env{}); got != "\x1b]52;c;aGk=\x07" {
		t.Fatalf("%q", got)
	}
	if got := Sequence("hi", Env{Screen: true}); got != "\x1bP\x1b]52;c;aGk=\x07\x1b\\" {
		t.Fatalf("%q", got)
	}
	want := "\x1b]52;c;aGk=\x07" + "\x1bPtmux;\x1b\x1b]52;c;aGk=\x07\x1b\\"
	if got := Sequence("hi", Env{Tmux: true}); got != want {
		t.Fatalf("%q", got)
	}
	var b bytes.Buffer
	if err := Copy(&b, "hi", Env{}); err != nil || b.String() != "\x1b]52;c;aGk=\x07" {
		t.Fatal(b.String(), err)
	}
}
