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
	keysPath := addKeysFlag(fs)
	who := fs.String("who", "", "only what concerns this person: the keys the keys file gives them (or, without one, keys with their name in the comment) and accounts with their name; for offboarding")
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
	owners, err := loadKeys(*keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: keys:", err)
		return exitUsage
	}
	if *who != "" && owners.Loaded() && !owners.Has(*who) {
		fmt.Fprintf(os.Stderr, "nobet: note: %s owns no key in %s; only accounts named %s will match\n", *who, owners.Path, *who)
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
	if owners.Loaded() {
		m.SetOwners(owners.Path, owners.Owner)
	}
	if *who != "" {
		m = m.Who(*who)
		if !*jsonOut {
			source := "the keys file " + m.OwnersFile
			if m.OwnersFile == "" {
				source = "key comments (no keys file, see -keys)"
			}
			fmt.Printf("Root access for %s: keys from %s, and accounts named %s.\n\n", *who, source, *who)
		}
	}
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
