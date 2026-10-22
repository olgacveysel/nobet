package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/olgacveysel/nobet/internal/report"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

// runReport writes the HTML and PDF reports from the saved history, without
// scanning: each host's newest successful scan.
func runReport(args []string) int {
	fs := flag.NewFlagSet("nobet report", flag.ContinueOnError)
	htmlPath := fs.String("html", "", "write the HTML report to this file")
	pdfPath := fs.String("pdf", "", "write the PDF report to this file")
	hostGlob := fs.String("host", "*", "only hosts matching this pattern (shell-style, e.g. 'web*')")
	keysPath := addKeysFlag(fs)
	histDir := addHistoryFlag(fs)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Write a report from saved scans, without scanning: each host's newest\n"+
			"successful scan. For a weekly report from cron, for example.\n\n"+
			"Usage:\n  nobet report -pdf report.pdf [-html report.html] [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *htmlPath == "" && *pdfPath == "" {
		fmt.Fprintln(os.Stderr, "nobet: say where to write the report: -pdf FILE, -html FILE or both")
		return exitUsage
	}
	if _, err := path.Match(*hostGlob, ""); err != nil {
		fmt.Fprintf(os.Stderr, "nobet: bad -host pattern %q\n", *hostGlob)
		return exitUsage
	}
	owners, err := loadKeys(*keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: keys:", err)
		return exitUsage
	}
	dir, err := historyDir(*histDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet:", err)
		return exitUsage
	}
	recent, hosts, err := store.Recent(dir, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: reading scan history:", err)
		return exitUsage
	}
	var results []scan.HostResult
	for _, h := range hosts {
		if ok, _ := path.Match(*hostGlob, h); !ok {
			continue
		}
		if snaps := recent[h]; len(snaps) > 0 {
			results = append(results, snaps[len(snaps)-1].Result())
		} else {
			results = append(results, scan.HostResult{Host: h, Error: "no successful scan in the history"})
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintf(os.Stderr, "nobet: no saved scans in %s; run 'nobet scan' first\n", dir)
		return exitUsage
	}
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "nobet: no host in the saved scans matches -host %q\n", *hostGlob)
		return exitUsage
	}
	now := time.Now()
	opened, err := store.OpenSince(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: reading scan history:", err)
	}
	for _, out := range []struct {
		path  string
		write func(p string) error
		name  string
	}{
		{*htmlPath, func(p string) error { return writeReport(p, report.HTML, results, now, owners, opened) }, "HTML"},
		{*pdfPath, func(p string) error { return writeReport(p, report.PDF, results, now, owners, opened) }, "PDF"},
	} {
		if out.path == "" {
			continue
		}
		if err := out.write(out.path); err != nil {
			fmt.Fprintf(os.Stderr, "nobet: writing the %s report: %v\n", out.name, err)
			return exitUsage
		}
		fmt.Printf("%s report of %d host(s) written to %s\n", out.name, len(results), out.path)
	}
	return exitOK
}
