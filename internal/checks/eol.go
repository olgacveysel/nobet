package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
)

//go:generate go run ./eolgen -o eol_data.go

// eolRelease holds a release's support dates (YYYY-MM-DD, "" if none):
// EOL is when the distribution stops publishing security updates for it,
// Extended when its paid or opt-in extended support ends.
type eolRelease struct {
	Version, EOL, Extended string
	LTS                    bool // a long-term release, where the distribution makes that distinction (Ubuntu)
}

// rolling distributions have no releases to support or retire.
var rolling = map[string]bool{
	"arch": true, "archarm": true, "endeavouros": true, "manjaro": true,
	"gentoo": true, "opensuse-tumbleweed": true, "void": true,
}

type eolProduct struct {
	Extended string // the extended support's name, e.g. "Expanded Security Maintenance"
	Releases []eolRelease
}

// eolWarnDays is how early UPD-004 warns about an approaching end of support.
const eolWarnDays = 180

// now is the time checks evaluate dates against; tests replace it.
var now = time.Now

var osSupport = Check{
	ID:    "UPD-004",
	Title: "Operating system support",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.OSRelease == nil {
			return nil, "could not read /etc/os-release: " + f.Errors["os-release"]
		}
		name := osName(f.OSRelease)
		key, version := eolKey(f.OSRelease)
		if rolling[key] || f.OSRelease["BUILD_ID"] == "rolling" {
			return nil, f.OSRelease["NAME"] + " is a rolling release, with no end of support"
		}
		if version == "" {
			return nil, name + " has no release version in /etc/os-release"
		}
		p, ok := eolData[key]
		if !ok {
			return nil, "no support dates known for " + name
		}
		var r eolRelease
		for _, c := range p.Releases {
			if c.Version == version {
				r = c
			}
		}
		if r.Version == "" {
			return nil, fmt.Sprintf("no support dates known for %s (this nöbet build has dates up to %s)", name, eolUpdated)
		}
		if r.EOL == "" {
			return nil, "" // no end announced yet
		}
		today := now().UTC().Truncate(24 * time.Hour)
		eol := day(r.EOL)
		left := days(today, eol)

		if left > eolWarnDays {
			return nil, ""
		}
		if left > 0 {
			return []Finding{{
				CheckID:  "UPD-004",
				Severity: Low,
				Title:    fmt.Sprintf("%s support ends on %s (in %d days)", name, r.EOL, left),
				Detail:   "after that the distribution publishes no more security updates for this release",
				Fix:      upgradeFix(p, today),
			}}, ""
		}

		// Past the end of support. Ubuntu's extended support is opt-in and
		// visible on the host; the others' is a paid contract nobet cannot see.
		if key == "ubuntu" && r.Extended != "" && contains(f.ExtendedSupport, "esm-infra") {
			left := days(today, day(r.Extended))
			switch {
			case left > eolWarnDays:
				return []Finding{{
					CheckID:  "UPD-004",
					Severity: Info,
					Title:    fmt.Sprintf("%s is on Ubuntu Pro ESM until %s", name, r.Extended),
					Detail:   fmt.Sprintf("standard support ended on %s; security updates now come from esm-infra", r.EOL),
				}}, ""
			case left > 0:
				return []Finding{{
					CheckID:  "UPD-004",
					Severity: Low,
					Title:    fmt.Sprintf("%s Ubuntu Pro ESM ends on %s (in %d days)", name, r.Extended, left),
					Detail:   fmt.Sprintf("standard support ended on %s; after ESM ends there are no more security updates", r.EOL),
					Fix:      upgradeFix(p, today),
				}}, ""
			}
		}
		detail := "the distribution has published no security updates for this release since then"
		if r.Extended != "" && days(today, day(r.Extended)) > 0 {
			switch {
			case key == "ubuntu" && f.ExtendedSupport == nil:
				detail += fmt.Sprintf("; Ubuntu Pro ESM runs until %s, but whether it is enabled could not be checked: %s", r.Extended, f.Errors["esm"])
			case key == "ubuntu":
				detail += fmt.Sprintf("; Ubuntu Pro ESM (esm-infra) would cover it until %s, and is not enabled", r.Extended)
			default:
				detail += fmt.Sprintf("; paid extended support (%s) runs until %s: if this host has it, allowlist this finding and say so", p.Extended, r.Extended)
			}
		}
		return []Finding{{
			CheckID:  "UPD-004",
			Severity: High,
			Title:    fmt.Sprintf("%s reached its end of support on %s", name, r.EOL),
			Detail:   detail,
			Fix:      upgradeFix(p, today),
		}}, ""
	},
}

// osName names the release as os-release does, e.g. "Ubuntu 20.04".
func osName(os map[string]string) string {
	n := os["NAME"]
	if n == "" {
		n = os["ID"]
	}
	if v := os["VERSION_ID"]; v != "" {
		n += " " + v
	}
	return n
}

// eolKey returns the eolData product and release for an os-release.
func eolKey(os map[string]string) (key, version string) {
	key, version = os["ID"], os["VERSION_ID"]
	switch key {
	case "raspbian":
		key, version = "debian", major(version)
	case "debian", "rhel", "rocky", "almalinux", "ol":
		version = major(version)
	case "centos":
		version = major(version)
		if strings.Contains(os["NAME"], "Stream") {
			key = "centos-stream"
		}
	case "alpine":
		if p := strings.Split(version, "."); len(p) >= 2 {
			version = p[0] + "." + p[1]
		}
	case "sles", "sles_sap":
		key = "sles"
		if version != "" && !strings.Contains(version, ".") {
			version += ".0" // SLES 15 without a service pack
		}
	}
	return key, version
}

// upgradeFix names the releases that are still supported, newest first;
// long-term ones only, where the distribution has them.
func upgradeFix(p eolProduct, today time.Time) string {
	lts := false
	for _, r := range p.Releases {
		lts = lts || r.LTS
	}
	var ok []string
	for _, r := range p.Releases {
		if len(ok) < 4 && (r.LTS || !lts) && (r.EOL == "" || days(today, day(r.EOL)) > eolWarnDays) {
			ok = append(ok, r.Version)
		}
	}
	if len(ok) == 0 {
		return "Move to a supported distribution; this one has no supported release left"
	}
	return "Upgrade to a supported release: " + strings.Join(ok, ", ")
}

func major(v string) string {
	m, _, _ := strings.Cut(v, ".")
	return m
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// days counts whole days from a to b; negative or zero once b has come.
func days(a, b time.Time) int {
	return int(b.Sub(a).Hours() / 24)
}
