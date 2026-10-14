package collect

import (
	"path"
	"regexp"
	"strings"
)

// Whose password sudo asks a user for, from the Defaults that apply.
const (
	SudoAuthUser   = "user"   // their own (the default)
	SudoAuthNone   = "none"   // nobody's: Defaults !authenticate
	SudoAuthTarget = "target" // the target's, so root's for rules that run as root: rootpw, targetpw, runaspw
)

// authFlags are the sudo Defaults that decide whose password is asked for.
var authFlags = set("authenticate", "rootpw", "targetpw", "runaspw")

// SudoDefaults are the authentication Defaults sudo applies to one user, as
// `sudo -l -U` reports them: the user's own, and those bound to a runas
// user (Defaults>root) or to commands (Defaults!/usr/bin/vim).
type SudoDefaults struct {
	Flags  map[string]bool `json:"flags,omitempty"`
	Scoped []ScopedDefault `json:"scoped,omitempty"`
}

// ScopedDefault is a Defaults entry bound to runas users (Kind ">") or to
// commands (Kind "!"). Only authentication flags are kept.
type ScopedDefault struct {
	Kind  string          `json:"kind"`
	List  []string        `json:"list"`
	Flags map[string]bool `json:"flags"`
}

// SudoAuthFor returns whose password sudo asks user for when running cmd
// (a command spec, or "ALL" for any command without its own Defaults) as
// runAs. sudo applies the user's Defaults, then runas-specific, then
// command-specific ones. NOPASSWD rules need no password either way.
func (f *Facts) SudoAuthFor(user, runAs, cmd string) string {
	flags := map[string]bool{"authenticate": true}
	d := f.SudoDefaults[user]
	for k, v := range d.Flags {
		flags[k] = v
	}
	for _, kind := range []string{">", "!"} {
		for _, s := range d.Scoped {
			if s.Kind != kind {
				continue
			}
			if kind == ">" && !matchRunAs(s.List, runAs) || kind == "!" && !matchCommand(s.List, cmd) {
				continue
			}
			for k, v := range s.Flags {
				flags[k] = v
			}
		}
	}
	switch {
	case !flags["authenticate"]:
		return SudoAuthNone
	case flags["rootpw"] || flags["targetpw"] || flags["runaspw"]:
		return SudoAuthTarget
	}
	return SudoAuthUser
}

func matchRunAs(list []string, runAs string) bool {
	for _, item := range list {
		if item == "ALL" || item == runAs {
			return true
		}
	}
	return false
}

// matchCommand reports whether a Defaults command list covers cmd. A
// listed command without arguments covers it with any arguments. "ALL"
// stands for any command not listed elsewhere, so only a Defaults!ALL
// entry applies to it.
func matchCommand(list []string, cmd string) bool {
	bin, args, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	for _, item := range list {
		if item == "ALL" {
			return true
		}
		if cmd == "ALL" {
			continue
		}
		ibin, iargs, hasArgs := strings.Cut(item, " ")
		if ok, _ := path.Match(ibin, bin); !ok {
			continue
		}
		if !hasArgs || strings.TrimSpace(iargs) == strings.TrimSpace(args) {
			return true
		}
	}
	return false
}

// readFlags keeps the authentication flags from a list of Defaults
// settings, later ones overriding earlier ones.
func readFlags(settings []string) map[string]bool {
	var flags map[string]bool
	for _, s := range settings {
		s = strings.TrimSpace(s)
		name := strings.TrimPrefix(s, "!")
		if authFlags[name] {
			if flags == nil {
				flags = map[string]bool{}
			}
			flags[name] = !strings.HasPrefix(s, "!")
		}
	}
	return flags
}

// scopedStart finds each "Defaults!" or "Defaults>" entry. sudo 1.9 may
// print several on one line.
var scopedStart = regexp.MustCompile(`Defaults[!>@]`)

// parseScoped reads the "Runas and Command-specific defaults" lines, for
// example:
//
//	Defaults>root targetpw    Defaults!/usr/bin/vim, /usr/bin/nano rootpw
//	Defaults!/usr/bin/less !authenticate
func parseScoped(text string) []ScopedDefault {
	var out []ScopedDefault
	locs := scopedStart.FindAllStringIndex(text, -1)
	for i, loc := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		kind := text[loc[1]-1 : loc[1]]
		if kind == "@" {
			continue // host-bound Defaults are already folded into the user's
		}
		list, settings, ok := splitBinding(text[loc[1]:end])
		if !ok {
			continue
		}
		if flags := readFlags(settings); flags != nil {
			out = append(out, ScopedDefault{Kind: kind, List: list, Flags: flags})
		}
	}
	return out
}

// splitBinding splits "/usr/bin/vim, /usr/bin/nano rootpw, !lecture" into
// the bound list and the settings. Settings never contain unquoted spaces,
// so words move into the bound list (as command arguments) until the rest
// reads as a settings list.
func splitBinding(body string) (list, settings []string, ok bool) {
	words := quotedFields(body)
	for i := 1; i < len(words); i++ {
		if strings.HasSuffix(words[i-1], ",") {
			continue // the bound list goes on
		}
		items := splitTopLevel(strings.Join(words[i:], " "))
		clean := true
		for _, it := range items {
			if strings.ContainsAny(unquoted(it), " \t") {
				clean = false
				break
			}
		}
		if !clean {
			continue
		}
		for _, l := range splitTopLevel(strings.Join(words[:i], " ")) {
			if l = strings.TrimSpace(l); l != "" {
				list = append(list, l)
			}
		}
		return list, items, true
	}
	return nil, nil, false
}

// quotedFields splits on whitespace outside double quotes.
func quotedFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// splitTopLevel splits on commas outside double quotes.
func splitTopLevel(s string) []string {
	var out []string
	start, inQuote := 0, false
	for i, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// unquoted drops double-quoted parts of s.
func unquoted(s string) string {
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
