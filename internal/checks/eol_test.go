package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
)

// withEOL runs the test on a fixed day and fixed support dates, so that
// refreshing eol_data.go never changes the results.
func withEOL(t *testing.T) {
	t.Helper()
	oldNow, oldData := now, eolData
	now = func() time.Time { return time.Date(2026, 10, 19, 15, 4, 5, 0, time.UTC) }
	eolData = map[string]eolProduct{
		"ubuntu": {Extended: "Expanded Security Maintenance", Releases: []eolRelease{
			{"26.10", "2027-07-01", "", false},
			{"26.04", "2031-05-29", "2036-04-23", true},
			{"24.04", "2029-05-31", "2034-04-25", true},
			{"22.04", "2027-03-01", "2032-04-21", true},
			{"20.04", "2025-05-31", "2030-04-23", true},
			{"16.04", "2021-04-02", "2026-12-01", true},
			{"14.04", "2019-04-02", "2024-04-02", true},
		}},
		"debian": {Extended: "ELTS", Releases: []eolRelease{
			{"13", "2030-06-30", "2035-06-30", false},
			{"12", "2028-06-30", "2033-06-30", false},
			{"11", "2026-08-31", "2031-06-30", false},
		}},
		"rhel": {Extended: "Extended Life Cycle Support", Releases: []eolRelease{
			{"9", "2032-05-31", "2036-05-31", false},
			{"7", "2024-06-30", "2029-05-31", false},
		}},
		"centos-stream": {Releases: []eolRelease{{"9", "2027-05-31", "", false}}},
		"centos":        {Releases: []eolRelease{{"7", "2024-06-30", "", false}}},
		"alpine":        {Releases: []eolRelease{{"3.22", "2027-05-01", "", false}, {"3.21", "2026-11-01", "", false}}},
		"sles":          {Extended: "Long Term Service Pack Support", Releases: []eolRelease{{"15.0", "2019-12-31", "2022-12-31", false}}},
		"fedora":        {Releases: []eolRelease{{"45", "", "", false}}},
	}
	t.Cleanup(func() { now, eolData = oldNow, oldData })
}

func osFacts(kv ...string) *collect.Facts {
	f := &collect.Facts{OSRelease: map[string]string{}, Errors: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.OSRelease[kv[i]] = kv[i+1]
	}
	return f
}

func TestOSSupport(t *testing.T) {
	withEOL(t)
	ubuntu := func(v string, esm []string) *collect.Facts {
		f := osFacts("ID", "ubuntu", "NAME", "Ubuntu", "VERSION_ID", v)
		f.ExtendedSupport = esm
		return f
	}
	cases := []struct {
		name   string
		f      *collect.Facts
		sev    Severity // -1: no finding
		title  string
		detail string
	}{
		{"supported", ubuntu("24.04", []string{}), -1, "", ""},
		{"ends soon", ubuntu("22.04", []string{}), Low, "Ubuntu 22.04 support ends on 2027-03-01 (in 133 days)", ""},
		{"past, no ESM", ubuntu("20.04", []string{}), High, "Ubuntu 20.04 reached its end of support on 2025-05-31", "esm-infra) would cover it until 2030-04-23, and is not enabled"},
		{"past, ESM apps only", ubuntu("20.04", []string{"esm-apps"}), High, "", "is not enabled"},
		{"past, on ESM", ubuntu("20.04", []string{"esm-infra", "esm-apps"}), Info, "Ubuntu 20.04 is on Ubuntu Pro ESM until 2030-04-23", "standard support ended on 2025-05-31"},
		{"ESM ends soon", ubuntu("16.04", []string{"esm-infra"}), Low, "Ubuntu 16.04 Ubuntu Pro ESM ends on 2026-12-01 (in 43 days)", ""},
		{"ESM over too", ubuntu("14.04", []string{"esm-infra"}), High, "Ubuntu 14.04 reached its end of support on 2019-04-02", ""},
		{"Debian LTS over", osFacts("ID", "debian", "NAME", "Debian GNU/Linux", "VERSION_ID", "11"), High, "Debian GNU/Linux 11 reached its end of support on 2026-08-31", "paid extended support (ELTS) runs until 2031-06-30"},
		{"Debian point release", osFacts("ID", "debian", "NAME", "Debian GNU/Linux", "VERSION_ID", "12"), -1, "", ""},
		{"Raspbian", osFacts("ID", "raspbian", "NAME", "Raspbian GNU/Linux", "VERSION_ID", "11"), High, "", ""},
		{"RHEL minor", osFacts("ID", "rhel", "NAME", "Red Hat Enterprise Linux", "VERSION_ID", "7.9"), High, "Red Hat Enterprise Linux 7.9 reached", "Extended Life Cycle Support"},
		{"RHEL 9", osFacts("ID", "rhel", "NAME", "Red Hat Enterprise Linux", "VERSION_ID", "9.4"), -1, "", ""},
		{"CentOS 7", osFacts("ID", "centos", "NAME", "CentOS Linux", "VERSION_ID", "7"), High, "", ""},
		{"CentOS Stream", osFacts("ID", "centos", "NAME", "CentOS Stream", "VERSION_ID", "9"), -1, "", ""},
		{"Alpine patch", osFacts("ID", "alpine", "NAME", "Alpine Linux", "VERSION_ID", "3.21.4"), Low, "Alpine Linux 3.21.4 support ends on 2026-11-01 (in 13 days)", ""},
		{"SLES without SP", osFacts("ID", "sles", "NAME", "SLES", "VERSION_ID", "15"), High, "", ""},
		{"no end announced", osFacts("ID", "fedora", "NAME", "Fedora Linux", "VERSION_ID", "45"), -1, "", ""},
	}
	for _, c := range cases {
		got, skip := osSupport.Run(c.f)
		if skip != "" {
			t.Errorf("%s: skipped: %s", c.name, skip)
			continue
		}
		if c.sev < 0 {
			if len(got) != 0 {
				t.Errorf("%s: got %+v, want no finding", c.name, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != c.sev || !strings.Contains(got[0].Title, c.title) || !strings.Contains(got[0].Detail, c.detail) {
			t.Errorf("%s: got %+v\nwant one %s finding titled %q with detail containing %q", c.name, got, c.sev, c.title, c.detail)
		}
	}
}

func TestOSSupportFix(t *testing.T) {
	withEOL(t)
	got, _ := osSupport.Run(osFacts("ID", "debian", "NAME", "Debian GNU/Linux", "VERSION_ID", "11"))
	// Releases past their end of support, or close to it, are not offered.
	if len(got) != 1 || got[0].Fix != "Upgrade to a supported release: 13, 12" {
		t.Errorf("got %+v", got)
	}
}

func TestOSSupportFixLTS(t *testing.T) {
	withEOL(t)
	got, _ := osSupport.Run(osFacts("ID", "ubuntu", "NAME", "Ubuntu", "VERSION_ID", "20.04"))
	if len(got) != 1 || got[0].Fix != "Upgrade to a supported release: 26.04, 24.04" {
		t.Errorf("got %+v", got)
	}
	got, _ = osSupport.Run(osFacts("ID", "centos", "NAME", "CentOS Linux", "VERSION_ID", "7"))
	if len(got) != 1 || !strings.HasPrefix(got[0].Fix, "Move to a supported distribution") {
		t.Errorf("got %+v", got)
	}
}

func TestOSSupportUnknownESM(t *testing.T) {
	withEOL(t)
	f := osFacts("ID", "ubuntu", "NAME", "Ubuntu", "VERSION_ID", "20.04")
	f.Errors["esm"] = "timeout"
	got, _ := osSupport.Run(f)
	if len(got) != 1 || got[0].Severity != High || !strings.Contains(got[0].Detail, "could not be checked: timeout") {
		t.Errorf("got %+v", got)
	}
}

func TestOSSupportSkips(t *testing.T) {
	withEOL(t)
	cases := map[string]*collect.Facts{
		"Arch Linux is a rolling release":            osFacts("ID", "arch", "NAME", "Arch Linux", "VERSION_ID", "20261018.0.612668"),
		"Tumbleweed is a rolling release":            osFacts("ID", "opensuse-tumbleweed", "NAME", "openSUSE Tumbleweed", "VERSION_ID", "20261015"),
		"has no release version":                     osFacts("ID", "debian", "NAME", "Debian GNU/Linux"),
		"no support dates known for Linux Mint 21.3": osFacts("ID", "linuxmint", "NAME", "Linux Mint", "VERSION_ID", "21.3"),
		"has dates up to":                            osFacts("ID", "ubuntu", "NAME", "Ubuntu", "VERSION_ID", "30.04"),
		"could not read":                             {Errors: map[string]string{"os-release": "No such file"}},
	}
	for want, f := range cases {
		got, skip := osSupport.Run(f)
		if len(got) != 0 || !strings.Contains(skip, want) {
			t.Errorf("%v: findings %+v, skip %q; want skip containing %q", f.OSRelease, got, skip, want)
		}
	}
}

// The generated table must be usable as it is: dates parse, versions are
// unique, and every product nobet maps to has releases.
func TestEOLData(t *testing.T) {
	if _, err := time.Parse("2006-01-02", eolUpdated); err != nil {
		t.Fatalf("eolUpdated %q: %v", eolUpdated, err)
	}
	for _, key := range []string{"almalinux", "alpine", "amzn", "centos", "centos-stream", "debian", "fedora", "ol", "opensuse-leap", "rhel", "rocky", "sles", "ubuntu"} {
		p, ok := eolData[key]
		if !ok || len(p.Releases) == 0 {
			t.Errorf("%s: no releases", key)
			continue
		}
		seen := map[string]bool{}
		for _, r := range p.Releases {
			if seen[r.Version] {
				t.Errorf("%s %s: listed twice", key, r.Version)
			}
			seen[r.Version] = true
			for _, d := range []string{r.EOL, r.Extended} {
				if _, err := time.Parse("2006-01-02", d); d != "" && err != nil {
					t.Errorf("%s %s: bad date %q", key, r.Version, d)
				}
			}
		}
	}
}
