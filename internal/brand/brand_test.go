package brand

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLinesMonochrome(t *testing.T) {
	lines := Lines(nil)
	if len(lines) != 7 {
		t.Fatalf("got %d lines, want 7", len(lines))
	}
	for i, l := range lines {
		if strings.Contains(l, "\x1b") {
			t.Errorf("line %d has escape codes in monochrome mode", i)
		}
		if n := utf8.RuneCountInString(l); n > Width() {
			t.Errorf("line %d is %d columns, wider than %d", i, n, Width())
		}
	}
	// The eyes are holes in monochrome: the eye row must contain gaps
	// inside the owl's face.
	if !strings.Contains(lines[1], "██  ██  ██") {
		t.Errorf("eye row looks wrong: %q", lines[1])
	}
}

func TestLinesColor(t *testing.T) {
	joined := strings.Join(Lines(ANSI), "\n")
	if !strings.Contains(joined, "\x1b[38;5;214m") {
		t.Error("color mode should paint the eyes amber")
	}
}
