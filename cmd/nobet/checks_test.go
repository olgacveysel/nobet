package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/checks"
)

func TestWriteChecks(t *testing.T) {
	var text bytes.Buffer
	if err := writeChecks(&text, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks.All() {
		if !strings.Contains(text.String(), c.ID+"  ") || !strings.Contains(text.String(), c.Title) {
			t.Errorf("%s %q missing from:\n%s", c.ID, c.Title, text.String())
		}
	}

	var js bytes.Buffer
	if err := writeChecks(&js, true); err != nil {
		t.Fatal(err)
	}
	var list []struct{ ID, Title string }
	if err := json.Unmarshal(js.Bytes(), &list); err != nil || len(list) != len(checks.All()) {
		t.Errorf("JSON: %v, %d entries", err, len(list))
	}
}

// Check IDs are what allowlists refer to: they must be unique and well-formed.
func TestCheckIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range checks.All() {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
		if prefix, num, ok := strings.Cut(c.ID, "-"); !ok || prefix == "" || len(num) != 3 {
			t.Errorf("check ID %q is not like ACC-002", c.ID)
		}
	}
}
