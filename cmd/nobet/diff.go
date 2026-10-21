package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/drift"
)

func runDiff(args []string) int {
	fs := flag.NewFlagSet("nobet diff", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print changes as JSON")
	fs.BoolVar(jsonOut, "j", false, "shorthand for -json")
	hostGlob := fs.String("host", "*", "only hosts matching this pattern (shell-style, e.g. 'web*')")
	sinceFlag := fs.String("since", "", "compare with each host's newest scan from before this long ago (7d, 2w, 36h) instead of its previous scan")
	histDir := addHistoryFlag(fs)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Show what changed on each host between its last two saved scans (or,\n"+
			"with -since, since a week or any time ago):\n"+
			"new routes to root, SSH keys, accounts and their passwords, group\n"+
			"memberships, sshd settings, listening ports and findings.\n\nUsage:\n  nobet diff [flags]\n\n"+
			"Exit status is 1 when there are changes, so cron can alert on it.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if _, err := path.Match(*hostGlob, ""); err != nil {
		fmt.Fprintf(os.Stderr, "nobet: bad -host pattern %q\n", *hostGlob)
		return exitUsage
	}

	dir, err := historyDir(*histDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet:", err)
		return exitUsage
	}
	var all []drift.HostDrift
	var once, never []string
	onceNote := "Only one successful scan so far"
	if *sinceFlag != "" {
		d, perr := parseSince(*sinceFlag)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "nobet: -since:", perr)
			return exitUsage
		}
		cutoff := time.Now().Add(-d)
		all, once, never, err = drift.Since(dir, cutoff)
		onceNote = "No successful scan from before " + cutoff.Format("2006-01-02 15:04") + " to compare with"
	} else {
		all, once, never, err = drift.Latest(dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet:", err)
		return exitUsage
	}
	var drifts []drift.HostDrift
	for _, d := range all {
		if ok, _ := path.Match(*hostGlob, d.Host); ok {
			drifts = append(drifts, d)
		}
	}
	matching := func(hosts []string) []string {
		var out []string
		for _, h := range hosts {
			if ok, _ := path.Match(*hostGlob, h); ok {
				out = append(out, h)
			}
		}
		return out
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if drifts == nil {
			drifts = []drift.HostDrift{}
		}
		if err := enc.Encode(drifts); err != nil {
			fmt.Fprintln(os.Stderr, "nobet:", err)
			return exitUsage
		}
	} else {
		if len(all)+len(once)+len(never) == 0 {
			fmt.Println("No saved scans yet. Run 'nobet scan' at least twice to see changes.")
			return exitOK
		}
		drift.WriteText(os.Stdout, drifts)
		if h := matching(once); len(h) > 0 {
			fmt.Printf("\n%s: %v\n", onceNote, h)
		}
		if h := matching(never); len(h) > 0 {
			fmt.Printf("\nNever scanned successfully: %v\n", h)
		}
		changes, hosts := drift.Count(drifts)
		fmt.Printf("\n%d change(s) on %d host(s)\n", changes, hosts)
	}

	if changes, _ := drift.Count(drifts); changes > 0 {
		return exitFindings
	}
	return exitOK
}

// parseSince reads a period such as 7d, 2w or 36h (any Go duration works).
func parseSince(v string) (time.Duration, error) {
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(v, suffix); ok {
			days, err := strconv.Atoi(n)
			if err != nil || days < 1 {
				return 0, fmt.Errorf("%q: want a period like 7d, 2w or 36h", v)
			}
			return time.Duration(days) * unit, nil
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q: want a period like 7d, 2w or 36h", v)
	}
	return d, nil
}
