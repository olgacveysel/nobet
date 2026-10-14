package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoWebCode keeps the CLI free of the dashboard and of any HTTP code:
// installing nobet must never bring a web server along.
func TestNoWebCode(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs the go command")
	}
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, d := range strings.Fields(string(out)) {
		if d == "net/http" || d == "github.com/olgacveysel/nobet/internal/web" {
			t.Errorf("the nobet CLI must not import %s", d)
		}
	}
}
