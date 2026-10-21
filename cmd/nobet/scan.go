package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/allow"
	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/drift"
	"github.com/olgacveysel/nobet/internal/keys"
	"github.com/olgacveysel/nobet/internal/queue"
	"github.com/olgacveysel/nobet/internal/report"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
	"github.com/olgacveysel/nobet/internal/tui"
)

// historyKeep is how many saved scans are kept for drift detection.
const historyKeep = 100

func runScan(args []string) int {
	fs := flag.NewFlagSet("nobet scan", flag.ContinueOnError)
	t := addTargetFlags(fs)
	jsonOut := fs.Bool("json", false, "print results as JSON")
	plain := fs.Bool("plain", false, "print a plain text report instead of opening the TUI")
	failOn := fs.String("fail-on", "high", "exit 1 if any finding is at or above this severity: info|low|medium|high|critical")
	allowPath := fs.String("allow", "", "allowlist file (default: "+displayPath(allow.DefaultPath())+" if it exists)")
	noSave := fs.Bool("no-save", false, "do not save this scan to the history used by 'nobet diff'")
	histDir := addHistoryFlag(fs)
	htmlPath := fs.String("html", "", "also write a self-contained HTML report (findings and root access map) to this file")
	pdfPath := fs.String("pdf", "", "also write the report as a PDF to this file")
	queueDir := fs.String("queue", "", "scan only what nobet-web users asked for in this queue directory, and only hosts from this command's own targets; does nothing when no request waits")
	keysPath := addKeysFlag(fs)
	onChange := fs.String("on-change", "", "run this shell command when the scan finds changes since the previous one, with them as JSON on stdin (as 'nobet diff -json') and the counts in $NOBET_CHANGES and $NOBET_CHANGED_HOSTS")
	fs.BoolVar(jsonOut, "j", false, "shorthand for -json")
	fs.BoolVar(plain, "p", false, "shorthand for -plain")
	fs.StringVar(failOn, "f", "high", "shorthand for -fail-on")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Audit security settings, updates and access.\n\nUsage:\n"+targetUsage, "scan")
		fmt.Fprint(fs.Output(), "\nIn an interactive terminal results open in the TUI. Piped or redirected\n"+
			"output, -plain and -json print plain output instead. Each scan is saved\n"+
			"so 'nobet diff' can show what changed.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	threshold, ok := checks.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "nobet: invalid -fail-on value %q\n", *failOn)
		return exitUsage
	}
	if !t.resolve(fs) {
		return exitUsage
	}
	if *queueDir != "" && *noSave {
		fmt.Fprintln(os.Stderr, "nobet: -queue records results in the scan history, so it cannot be used with -no-save")
		return exitUsage
	}
	var claimed []queue.Request
	var ignored []string
	if *queueDir != "" {
		if err := queue.Recover(*queueDir, time.Hour, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "nobet: scan queue:", err)
			return exitUsage
		}
		var err error
		if claimed, err = queue.Claim(*queueDir); err != nil {
			fmt.Fprintln(os.Stderr, "nobet: scan queue:", err)
			return exitUsage
		}
		if len(claimed) == 0 {
			return exitOK // nothing asked for
		}
		if hosts := queue.Hosts(claimed); hosts != nil {
			ignored = t.only(hosts)
		}
		for _, r := range claimed {
			fmt.Fprintf(os.Stderr, "nobet: scan requested by %s at %s\n", orAnyone(r.User), r.Time.Local().Format("15:04"))
		}
		if len(ignored) > 0 {
			fmt.Fprintf(os.Stderr, "nobet: not in this scan's targets, so not scanned: %s\n", strings.Join(ignored, ", "))
		}
		if !t.doLocal && len(t.hosts) == 0 {
			finishQueue(*queueDir, claimed, nil, ignored, time.Now(), "none of the requested hosts are in the scanner's inventory")
			return exitOK
		}
	}
	if *onChange != "" && *noSave {
		fmt.Fprintln(os.Stderr, "nobet: -on-change compares with the saved history, so it cannot be used with -no-save")
		return exitUsage
	}

	allowList, err := loadAllowlist(*allowPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: allowlist:", err)
		return exitUsage
	}
	owners, err := loadKeys(*keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: keys:", err)
		return exitUsage
	}
	started := time.Now()

	var results []scan.HostResult
	tuiMode := !*jsonOut && !*plain && *queueDir == "" && isTerminal(os.Stdout) && isTerminal(os.Stdin)
	if tuiMode {
		names := t.names()
		results, err = tui.Run(names, owners, func(report func(int, scan.HostResult)) {
			t.run(func(i int, r scan.HostResult) {
				allowList.Apply(&r)
				report(i, r)
			})
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet: TUI failed:", err)
			return exitUsage
		}
		report.Summary(os.Stdout, results)
		if n := len(names) - len(results); n > 0 {
			fmt.Printf("(%d host(s) were still being scanned when you quit)\n", n)
		}
	} else {
		results = t.run(nil)
		for i := range results {
			allowList.Apply(&results[i])
		}
		if *jsonOut {
			if err := report.JSON(os.Stdout, results); err != nil {
				fmt.Fprintln(os.Stderr, "nobet:", err)
				return exitUsage
			}
		} else {
			report.Text(os.Stdout, results)
		}
	}

	if *htmlPath != "" {
		if err := writeReport(*htmlPath, report.HTML, results, started, owners); err != nil {
			fmt.Fprintln(os.Stderr, "nobet: writing HTML report:", err)
		} else if !*jsonOut {
			fmt.Printf("HTML report written to %s\n", *htmlPath)
		}
	}
	if *pdfPath != "" {
		if err := writeReport(*pdfPath, report.PDF, results, started, owners); err != nil {
			fmt.Fprintln(os.Stderr, "nobet: writing PDF report:", err)
		} else if !*jsonOut {
			fmt.Printf("PDF report written to %s\n", *pdfPath)
		}
	}

	if !*noSave {
		// Drift notes go to stderr in JSON mode so stdout stays valid JSON.
		out := os.Stdout
		if *jsonOut {
			out = os.Stderr
		}
		saveAndSummarize(out, *histDir, results, started, *onChange)
	}
	if len(claimed) > 0 {
		finishQueue(*queueDir, claimed, results, ignored, started, "")
	}
	return exitCode(results, threshold)
}

// finishQueue records the outcome of the requests a -queue scan handled.
func finishQueue(dir string, claimed []queue.Request, results []scan.HostResult, ignored []string, started time.Time, errMsg string) {
	var done []queue.Done
	for _, r := range claimed {
		want := map[string]bool{}
		for _, h := range r.Hosts {
			want[h] = true
		}
		d := queue.Done{Request: r, Started: started.UTC(), Finished: time.Now().UTC(), Error: errMsg}
		for _, res := range results {
			if len(r.Hosts) > 0 && !want[res.Host] {
				continue
			}
			d.Scanned = append(d.Scanned, res.Host)
			if res.Error != "" {
				d.Unreachable = append(d.Unreachable, res.Host)
			}
		}
		for _, h := range ignored {
			if want[h] {
				d.Ignored = append(d.Ignored, h)
			}
		}
		done = append(done, d)
	}
	if err := queue.Finish(dir, done); err != nil {
		fmt.Fprintln(os.Stderr, "nobet: scan queue:", err)
	}
}

func orAnyone(user string) string {
	if user == "" {
		return "a dashboard user"
	}
	return user
}

// writeReport writes an HTML or PDF report. The file is 0600 because it
// lists security weaknesses and access paths.
func writeReport(p string, write func(io.Writer, []scan.HostResult, report.HTMLMeta) error, results []scan.HostResult, at time.Time, owners *keys.Owners) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := write(f, results, report.HTMLMeta{Generated: at, Version: version, Owners: owners}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// addKeysFlag adds -keys, the file that names the owners of SSH keys.
func addKeysFlag(fs *flag.FlagSet) *string {
	return fs.String("keys", "", "file naming who each SSH key belongs to, for the root access map (default: "+displayPath(keys.DefaultPath())+" if it exists)")
}

// loadKeys loads an explicit keys file (which must exist) or the default
// one (which is optional).
func loadKeys(p string) (*keys.Owners, error) {
	if p != "" {
		return keys.Load(p, true)
	}
	return keys.Load(keys.DefaultPath(), false)
}

// loadAllowlist loads an explicit allowlist (which must exist) or the
// default one (which is optional).
func loadAllowlist(p string) (*allow.List, error) {
	if p != "" {
		return allow.Load(p, true)
	}
	return allow.Load(allow.DefaultPath(), false)
}

// saveAndSummarize stores the scan and prints a one-line drift summary
// against each host's previous scan, then runs the -on-change command if
// anything changed. History problems never fail a scan.
func saveAndSummarize(out *os.File, histDir string, results []scan.HostResult, at time.Time, onChange string) {
	dir, err := historyDir(histDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: scan history unavailable:", err)
		return
	}
	prev, _, err := store.Recent(dir, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet: reading scan history:", err)
	}

	var drifts []drift.HostDrift
	for _, r := range results {
		if r.Error != "" || r.Facts == nil || len(prev[r.Host]) == 0 {
			continue
		}
		drifts = append(drifts, drift.Compare(prev[r.Host][0], store.FromResult(r, at.UTC())))
	}

	if _, err := store.Save(dir, results, at); err != nil {
		fmt.Fprintln(os.Stderr, "nobet: saving scan history:", err)
		return
	}
	_ = store.Prune(dir, historyKeep)

	if changes, hosts := drift.Count(drifts); changes > 0 {
		fmt.Fprintf(out, "%d change(s) on %d host(s) since the previous scan. Run 'nobet diff' for details.\n", changes, hosts)
		if onChange != "" {
			runHook(onChange, drifts)
		}
	}
}

func exitCode(results []scan.HostResult, threshold checks.Severity) int {
	failing, unreachable := false, false
	for _, r := range results {
		if r.Error != "" {
			unreachable = true
		}
		for _, f := range r.Findings {
			if f.Severity >= threshold {
				failing = true
			}
		}
	}
	switch {
	case failing:
		return exitFindings
	case unreachable:
		return exitUnreachable
	}
	return exitOK
}

// addHistoryFlag adds -history-dir, shared by scan and diff.
func addHistoryFlag(fs *flag.FlagSet) *string {
	return fs.String("history-dir", "", "scan history directory (default: $NOBET_DATA_DIR/scans, or ~/.local/share/nobet/scans)")
}

// historyDir returns the -history-dir value, or the default location.
func historyDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return store.Dir()
}

// displayPath shortens a path under the home directory to ~/...
func displayPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" && len(p) > len(home) && p[:len(home)] == home {
		return "~" + p[len(home):]
	}
	return p
}
