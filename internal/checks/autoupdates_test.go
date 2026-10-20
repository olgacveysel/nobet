package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestAutoUpdates(t *testing.T) {
	cases := []struct {
		name    string
		manager string
		a       map[string]string
		want    string // "" for no finding; otherwise part of the detail
	}{
		{"ubuntu, enabled", "apt", map[string]string{"unattended-upgrades": "installed", "periodic.Unattended-Upgrade": "1", "periodic.Update-Package-Lists": "1", "unit.apt-daily-upgrade.timer": "enabled"}, ""},
		{"docker image", "apt", map[string]string{"unit.apt-daily-upgrade.timer": "enabled"}, "unattended-upgrades is not installed"},
		{"turned off", "apt", map[string]string{"unattended-upgrades": "installed", "periodic.Unattended-Upgrade": "0", "periodic.Update-Package-Lists": "1"}, "Unattended-Upgrade is 0"},
		{"no list updates", "apt", map[string]string{"unattended-upgrades": "installed", "periodic.Unattended-Upgrade": "1"}, "Update-Package-Lists is not set"},
		{"timer masked", "apt", map[string]string{"unattended-upgrades": "installed", "periodic.Unattended-Upgrade": "1", "periodic.Update-Package-Lists": "1", "unit.apt-daily-upgrade.timer": "masked"}, "apt-daily-upgrade.timer, which runs them, is masked"},
		{"rhel, install timer", "dnf", map[string]string{"unit.dnf-automatic-install.timer": "enabled", "unit.dnf-automatic.timer": "disabled", "apply./etc/dnf/automatic.conf": "no"}, ""},
		{"rhel, apply_updates yes", "dnf", map[string]string{"unit.dnf-automatic.timer": "enabled", "apply./etc/dnf/automatic.conf": "yes"}, ""},
		{"rhel, download only", "dnf", map[string]string{"unit.dnf-automatic.timer": "enabled", "apply./etc/dnf/automatic.conf": "no"}, "dnf-automatic.timer is enabled but only downloads"},
		{"rhel, nothing", "dnf", map[string]string{}, "no dnf-automatic"},
		{"fedora dnf5", "dnf5", map[string]string{"unit.dnf5-automatic.timer": "enabled", "apply./usr/share/dnf5/dnf5-plugins/automatic.conf": "no", "apply./etc/dnf/dnf5-plugins/automatic.conf": "yes"}, ""},
		{"centos 7", "yum", map[string]string{"unit.yum-cron.service": "enabled", "apply./etc/yum/yum-cron.conf": "yes"}, ""},
	}
	for _, c := range cases {
		f := &collect.Facts{Updates: &collect.Updates{Manager: c.manager}, AutoUpdates: c.a}
		got, skip := autoUpdates.Run(f)
		switch {
		case skip != "":
			t.Errorf("%s: skipped: %s", c.name, skip)
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: got %+v, want none", c.name, got)
		case c.want != "" && (len(got) != 1 || got[0].Severity != Low || !strings.Contains(got[0].Detail, c.want)):
			t.Errorf("%s: got %+v, want a Low finding with %q", c.name, got, c.want)
		}
	}

	skips := map[string]*collect.Facts{
		"no standard automatic update": {Updates: &collect.Updates{Manager: "apk"}, AutoUpdates: map[string]string{}},
		"could not check":              {Errors: map[string]string{"autoupdates": "timeout"}},
	}
	for want, f := range skips {
		if got, skip := autoUpdates.Run(f); len(got) != 0 || !strings.Contains(skip, want) {
			t.Errorf("%v: got %+v, skip %q", f.Updates, got, skip)
		}
	}
}
