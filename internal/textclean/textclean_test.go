package textclean

import (
	"reflect"
	"testing"
)

func TestString(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, ünïcode ok":            "plain text, ünïcode ok",
		"a\tb\nc":                           "a\tb\nc",
		"key \x1b]0;pwned\x07 comment":      "key ?]0;pwned? comment", // OSC: sets the window title
		"\x1b[2J\x1b[1;1Hfake prompt$ ":     "?[2J?[1;1Hfake prompt$ ",
		"c1 csi \u009b31m red":              "c1 csi ?31m red",
		"carriage\rreturn overwrites lines": "carriage?return overwrites lines",
	} {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

type inner struct {
	Comment string
	Tags    []string
	hidden  string
}

type outer struct {
	Name   string
	Ptr    *inner
	List   []inner
	ByUser map[string][]string
	Errors map[string]string
	Any    any
	Num    int
}

func TestStrings(t *testing.T) {
	v := outer{
		Name:   "host\x1b[31m",
		Ptr:    &inner{Comment: "me@laptop\x1b]0;x\x07", Tags: []string{"ok", "bad\u009b"}, hidden: "\x1b"},
		List:   []inner{{Comment: "\x1b"}},
		ByUser: map[string][]string{"alice\x1b": {"/home/alice\x1b[0m"}},
		Errors: map[string]string{"sshd": "error: \x1b[2Jcleared"},
		Any:    &inner{Comment: "\x07"},
		Num:    7,
	}
	Strings(&v)
	want := outer{
		Name:   "host?[31m",
		Ptr:    &inner{Comment: "me@laptop?]0;x?", Tags: []string{"ok", "bad?"}, hidden: "\x1b"},
		List:   []inner{{Comment: "?"}},
		ByUser: map[string][]string{"alice?": {"/home/alice?[0m"}},
		Errors: map[string]string{"sshd": "error: ?[2Jcleared"},
		Any:    &inner{Comment: "?"},
		Num:    7,
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("got  %#v\nwant %#v", v, want)
	}
	Strings(nil)                       // no panic
	Strings(&outer{})                  // nil maps and pointers
	Strings(map[string]int{"\x1b": 1}) // a map passed by value still cleans in place
}
