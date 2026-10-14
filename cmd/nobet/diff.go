package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/olgacveysel/nobet/internal/drift"
)

func runDiff(args []string) int {
	fs := flag.NewFlagSet("nobet diff", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print changes as JSON")
	fs.BoolVar(jsonOut, "j", false, "shorthand for -json")
	hostGlob := fs.String("host", "*", "only hosts matching this pattern (shell-style, e.g. 'web*')")
	histDir := addHistoryFlag(fs)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Show what changed on each host between its last two saved scans:\n"+
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
	all, once, never, err := drift.Latest(dir)
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
			fmt.Printf("\nOnly one successful scan so far: %v\n", h)
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
