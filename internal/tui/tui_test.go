package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func send(m model, msgs ...tea.Msg) model {
	for _, msg := range msgs {
		next, _ := m.Update(msg)
		m = next.(model)
	}
	return m
}

// TestModel drives the model through a scan at several window sizes,
// including tiny ones, and checks that views render without panicking.
func TestModel(t *testing.T) {
	var findings []checks.Finding
	for i := 0; i < 30; i++ {
		findings = append(findings, checks.Finding{CheckID: "SSH-001", Severity: checks.Severity(i % 5),
			Title: "a finding with a reasonably long title that will need wrapping", Detail: "detail", Fix: "fix"})
	}
	web := scan.HostResult{Host: "web01", OS: "Ubuntu 24.04", Privileged: true, Findings: findings,
		Facts: &collect.Facts{IsRoot: true, Passwd: []collect.PasswdEntry{{Name: "root"}},
			AuthKeys: []collect.AuthKey{{User: "root", Fingerprint: "SHA256:k", Type: "ssh-ed25519"}}}}
	db := scan.HostResult{Host: "db01", Error: "connection refused"}

	for _, size := range [][2]int{{0, 0}, {10, 3}, {40, 10}, {80, 24}, {200, 60}} {
		m := model{names: []string{"web01", "db01", "a-very-long-host-name.example.internal"},
			results: make([]scan.HostResult, 3), done: make([]bool, 3)}
		m = send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]}, tickMsg{})
		_ = m.View() // host still scanning: shows the owl
		m = send(m, hostDoneMsg{0, web}, hostDoneMsg{1, db}, hostDoneMsg{0, web})
		if m.ndone != 2 {
			t.Fatalf("ndone = %d after a duplicate report, want 2", m.ndone)
		}
		for _, k := range []string{"pgdown", "pgdown", "f", "f", "f", "f", "f", "down", "down", "down", "G", "g", "r", "pgdown"} {
			m = send(m, key(k))
			_ = m.View()
		}
		m = send(m, scanDoneMsg{}, key("r"))
		v := m.View()
		if size[0] >= 80 && !strings.Contains(v, "web01") {
			t.Errorf("%dx%d: view lacks host name:\n%s", size[0], size[1], v)
		}
		if m.scroll < 0 || m.scroll > m.maxScroll() {
			t.Errorf("%dx%d: scroll %d out of range [0,%d]", size[0], size[1], m.scroll, m.maxScroll())
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := map[string]string{"short": "short", "exactly10!": "exactly10!", "much longer name": "much long…"}
	for in, want := range cases {
		if got := truncate(in, 10); got != want {
			t.Errorf("truncate(%q) = %q, want %q", in, got, want)
		}
	}
	if got := truncate("öbetöbetöbet", 5); got != "öbet…" {
		t.Errorf("multibyte: %q", got)
	}
}
