package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/olgacveysel/nobet/internal/checks"
)

func runChecks(args []string) int {
	fs := flag.NewFlagSet("nobet checks", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "print the list as JSON")
	fs.BoolVar(jsonOut, "j", false, "shorthand for -json")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "List every check, for example to write allowlist rules.\n\nUsage:\n  nobet checks [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "nobet: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if err := writeChecks(os.Stdout, *jsonOut); err != nil {
		fmt.Fprintln(os.Stderr, "nobet:", err)
		return exitUsage
	}
	return exitOK
}

func writeChecks(w io.Writer, asJSON bool) error {
	type item struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	var list []item
	for _, c := range checks.All() {
		list = append(list, item{c.ID, c.Title})
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range list {
		fmt.Fprintf(tw, "%s\t%s\n", c.ID, c.Title)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, "\nTo accept a reviewed finding, add a line to the allowlist (see allowlist.example):\n"+
		"  ACC-002  web*  deploy   # our deploy account needs NOPASSWD\n")
	return err
}
