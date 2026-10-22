// Package allow implements the allowlist: findings you have reviewed and
// accept, so reports only show what still needs attention.
//
// The file has one rule per line:
//
//	<check-id>  <host-glob>  [text to match]   # reason
//
// For example:
//
//	ACC-002  *       nobet-scan        # our scanning account needs NOPASSWD
//	NET-001  web*    tcp/443           # public web servers
//	UPD-002  db01                      # rebooted in the Sunday window
//	*        lab-*                     # lab machines are out of scope
//	CTR-001  *       traefik  until=2027-01-31  # needs the socket; review
//
// The check ID may be * for any check. The host glob uses shell-style
// patterns (*, ?, [abc]). The optional match text must appear in the
// finding's title or detail (case-insensitive, whitespace-normalized).
// Everything after a # that starts a word is the reason.
//
// A word until=YYYY-MM-DD makes the rule expire: it covers findings through
// that day (in the scanning machine's time zone) and none after it, so an
// accepted risk comes back for review. Scans note rules that have expired
// or expire within two weeks.
package allow

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
)

// Rule is one allowlist entry.
type Rule struct {
	CheckID string `json:"check_id"`
	Host    string `json:"host"`
	Match   string `json:"match,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Until   string `json:"until,omitempty"` // last day the rule applies, YYYY-MM-DD; "" for always
	Line    int    `json:"line"`
}

// List is a loaded allowlist. The zero value allows nothing.
type List struct {
	Path  string
	Rules []Rule
}

// DefaultPath is ~/.config/nobet/allowlist (or the platform equivalent).
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "nobet", "allowlist")
}

// Load reads an allowlist. A missing file is an error only when required
// is true, so the default location can be optional.
func Load(p string, required bool) (*List, error) {
	if p == "" {
		return &List{}, nil
	}
	f, err := os.Open(p)
	if err != nil {
		if !required && errors.Is(err, fs.ErrNotExist) {
			return &List{}, nil
		}
		return nil, err
	}
	defer f.Close()
	rules, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &List{Path: p, Rules: rules}, nil
}

// Parse reads rules from r.
func Parse(r io.Reader) ([]Rule, error) {
	var rules []Rule
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, reason := splitComment(sc.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want <check-id> <host-glob> [match text]", n)
		}
		id := strings.ToUpper(fields[0])
		if id != "*" && !strings.Contains(id, "-") {
			return nil, fmt.Errorf("line %d: %q is not a check ID like ACC-002 (or *)", n, fields[0])
		}
		if _, err := path.Match(fields[1], ""); err != nil {
			return nil, fmt.Errorf("line %d: bad host pattern %q", n, fields[1])
		}
		var match []string
		until := ""
		for _, w := range fields[2:] {
			d, ok := strings.CutPrefix(strings.ToLower(w), "until=")
			if !ok {
				match = append(match, w)
				continue
			}
			if _, err := time.Parse(time.DateOnly, d); err != nil || until != "" {
				return nil, fmt.Errorf("line %d: %q: want one until=YYYY-MM-DD", n, w)
			}
			until = d
		}
		rules = append(rules, Rule{
			CheckID: id,
			Host:    fields[1],
			Match:   strings.Join(match, " "),
			Reason:  reason,
			Until:   until,
			Line:    n,
		})
	}
	return rules, sc.Err()
}

// splitComment splits off a # comment that starts the line or follows
// whitespace, so a # inside match text (like "C#") is kept.
func splitComment(s string) (line, comment string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i], strings.TrimSpace(s[i+1:])
		}
	}
	return s, ""
}

// Find returns the first rule that covers finding f on host on the given
// day (YYYY-MM-DD): rules that expired before it do not.
func (l *List) Find(host string, f checks.Finding, day string) (Rule, bool) {
	if l == nil {
		return Rule{}, false
	}
	text := normalize(f.Title + " " + f.Detail)
	for _, r := range l.Rules {
		if r.Until != "" && day > r.Until {
			continue
		}
		if r.CheckID != "*" && !strings.EqualFold(r.CheckID, f.CheckID) {
			continue
		}
		if ok, _ := path.Match(r.Host, host); !ok {
			continue
		}
		if r.Match != "" && !strings.Contains(text, normalize(r.Match)) {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// Apply moves findings covered by the list today from r.Findings to
// r.Suppressed.
func (l *List) Apply(r *scan.HostResult) { l.ApplyAt(r, time.Now()) }

// ApplyAt is Apply as of the day now falls on.
func (l *List) ApplyAt(r *scan.HostResult, now time.Time) {
	if l == nil || len(l.Rules) == 0 {
		return
	}
	day := now.Format(time.DateOnly)
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		if rule, ok := l.Find(r.Host, f, day); ok {
			r.Suppressed = append(r.Suppressed, scan.Suppressed{
				Finding: f,
				Reason:  rule.Reason,
				Until:   rule.Until,
				Rule:    fmt.Sprintf("%s:%d", filepath.Base(l.Path), rule.Line),
			})
			continue
		}
		kept = append(kept, f)
	}
	r.Findings = kept
}

// soonDays is how many days before a rule ends scans start to mention it.
const soonDays = 14

// Notes describes the rules that have expired as of now, and those that
// expire within two weeks.
func (l *List) Notes(now time.Time) []string {
	if l == nil {
		return nil
	}
	today, _ := time.ParseInLocation(time.DateOnly, now.Format(time.DateOnly), now.Location())
	var out []string
	for _, r := range l.Rules {
		if r.Until == "" {
			continue
		}
		end, _ := time.ParseInLocation(time.DateOnly, r.Until, now.Location())
		left := int(math.Round(end.Sub(today).Hours()/24)) + 1 // days it still covers, today included
		what := fmt.Sprintf("rule %s:%d (%s %s", filepath.Base(l.Path), r.Line, r.CheckID, r.Host)
		if r.Match != "" {
			what += " " + r.Match
		}
		what += ")"
		switch {
		case left <= 0:
			out = append(out, what+" ended on "+r.Until+"; the findings it covered count again")
		case left <= soonDays:
			out = append(out, fmt.Sprintf("%s covers findings until %s (%d more day(s)); review it", what, r.Until, left))
		}
	}
	return out
}

func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
