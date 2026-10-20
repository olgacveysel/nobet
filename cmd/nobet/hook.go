package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/drift"
)

// hookTimeout bounds an -on-change command, so a hung webhook never keeps
// a scheduled scan from finishing.
const hookTimeout = 2 * time.Minute

// hookSummaryLines caps the changes listed in NOBET_SUMMARY.
const hookSummaryLines = 20

// runHook runs the -on-change command with the hosts that changed as JSON
// on stdin (the format of `nobet diff -json`), the totals in NOBET_CHANGES
// and NOBET_CHANGED_HOSTS, and a short text in NOBET_SUMMARY (also as a
// JSON string in NOBET_SUMMARY_JSON, so a hook can post it without jq). Its
// output goes to stderr, so -json output stays valid, and its failure is
// reported but never fails the scan.
func runHook(command string, drifts []drift.HostDrift) {
	changed := []drift.HostDrift{}
	for _, d := range drifts {
		if len(d.Changes) > 0 {
			changed = append(changed, d)
		}
	}
	changes, hosts := drift.Count(changed)
	data, err := json.MarshalIndent(changed, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: -on-change:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	cmd := shellCommand(ctx, command)
	cmd.Stdin = bytes.NewReader(append(data, '\n'))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	summary := hookSummary(changed, changes, hosts)
	summaryJSON, _ := json.Marshal(summary)
	cmd.Env = append(os.Environ(), "NOBET_CHANGES="+strconv.Itoa(changes), "NOBET_CHANGED_HOSTS="+strconv.Itoa(hosts),
		"NOBET_SUMMARY="+summary, "NOBET_SUMMARY_JSON="+string(summaryJSON))
	cmd.WaitDelay = 5 * time.Second // do not wait for children that keep the output open
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("stopped after %v", hookTimeout)
		}
		fmt.Fprintf(os.Stderr, "nobet: -on-change command failed: %v\n", err)
	}
}

// hookSummary is a few lines for a chat message or mail subject.
func hookSummary(changed []drift.HostDrift, changes, hosts int) string {
	lines := []string{fmt.Sprintf("nöbet: %d change(s) on %d host(s)", changes, hosts)}
	n := 0
	for _, d := range changed {
		for _, c := range d.Changes {
			if n++; n <= hookSummaryLines {
				lines = append(lines, fmt.Sprintf("%s: %s %s: %s", d.Host, c.Kind, c.Area, c.What))
			}
		}
	}
	if n > hookSummaryLines {
		lines = append(lines, fmt.Sprintf("(and %d more; run nobet diff)", n-hookSummaryLines))
	}
	return strings.Join(lines, "\n")
}

func shellCommand(ctx context.Context, command string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", command)
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", command)
}
