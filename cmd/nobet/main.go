// Command nobet audits the security of Linux servers, locally or over SSH.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/olgacveysel/nobet/internal/brand"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

// Exit codes, shared by all commands.
const (
	exitOK          = 0
	exitFindings    = 1 // at least one finding at or above -fail-on
	exitUsage       = 2
	exitUnreachable = 3 // no failing findings, but some hosts could not be scanned
)

const usage = `Usage:
  nobet <command> [flags]

Commands:
  scan, s          Audit this machine, or remote hosts over SSH
  rootmap, r       Show who can become root on which host, and how
  diff, d          Show what changed since the previous scan
  checks, c        List every check (IDs for the allowlist)
  version, -v      Print the version
  help, -h         Show help for a command

Run "nobet help <command>" or "nobet <command> -h" for details.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		printBanner(os.Stderr)
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "scan", "s":
		return runScan(rest)
	case "rootmap", "r":
		return runRootmap(rest)
	case "diff", "d":
		return runDiff(rest)
	case "checks", "c":
		return runChecks(rest)
	case "version", "v", "-v", "-version", "--version":
		// Scripts parse `nobet version`, so the logo only goes to terminals.
		if isTerminal(os.Stdout) {
			printBanner(os.Stdout)
		}
		fmt.Println("nobet", version)
		return exitOK
	case "help", "h", "-h", "-help", "--help":
		if len(rest) > 0 {
			switch rest[0] {
			case "scan", "s":
				return runScan([]string{"-h"})
			case "rootmap", "r":
				return runRootmap([]string{"-h"})
			case "diff", "d":
				return runDiff([]string{"-h"})
			case "checks", "c":
				return runChecks([]string{"-h"})
			}
		}
		printBanner(os.Stdout)
		fmt.Print(usage)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "nobet: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

// printBanner writes the owl logo and tagline. Color is used only on a
// terminal, and never when NO_COLOR is set (https://no-color.org).
func printBanner(w *os.File) {
	var paint brand.Painter
	if isTerminal(w) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		paint = brand.ANSI
	}
	writeBanner(w, paint)
}

func writeBanner(w io.Writer, paint brand.Painter) {
	fmt.Fprintln(w)
	for _, l := range brand.Lines(paint) {
		fmt.Fprintln(w, "  "+l)
	}
	fmt.Fprintf(w, "\n  nöbet · %s\n\n", brand.Tagline)
}
