package term

import (
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	got := Decode([]byte("j\x1b[A\x1b[6~\r\x1b\x7fé\x03\x1bOB"))
	want := []Key{
		{Rune: 'j'}, {Name: "up"}, {Name: "pgdn"}, {Name: "enter"}, {Name: "esc"},
		{Name: "backspace"}, {Rune: 'é'}, {Name: "ctrl+c"}, {Name: "down"},
	}
	// "\x1b\x7f" is alt+backspace, decoded as esc then backspace.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if Decode([]byte("\x1b"))[0].Name != "esc" {
		t.Fatal("lone esc")
	}
	if k := (Key{Rune: 'q'}); k.String() != "q" {
		t.Fatal(k.String())
	}
}
