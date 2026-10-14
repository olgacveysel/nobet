package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
)

func runRootmap(args []string) int {
	fs := flag.NewFlagSet("nobet rootmap", flag.ContinueOnError)
	t := addTargetFlags(fs)
	jsonOut := fs.Bool("json", false, "print the map as JSON")
	fs.BoolVar(jsonOut, "j", false, "shorthand for -json")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Show who can become root on which host, and how, grouped by SSH key.\n\nUsage:\n"+targetUsage, "rootmap")
		fmt.Fprint(fs.Output(), "\nFull results need root or passwordless sudo on every host.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if !t.resolve(fs) {
		return exitUsage
	}

	var progress func(int, scan.HostResult)
	total := len(t.names())
	if isTerminal(os.Stderr) {
		var done atomic.Int32
		progress = func(int, scan.HostResult) {
			fmt.Fprintf(os.Stderr, "\rscanning %d/%d hosts…", done.Add(1), total)
		}
	}
	results := t.run(progress)
	if progress != nil {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}

	m := rootmap.Build(results)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			fmt.Fprintln(os.Stderr, "nobet:", err)
			return exitUsage
		}
	} else {
		m.WriteText(os.Stdout)
	}

	for _, r := range results {
		if r.Error != "" {
			return exitUnreachable
		}
	}
	return exitOK
}
