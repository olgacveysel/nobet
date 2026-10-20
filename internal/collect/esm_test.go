package collect

import (
	"reflect"
	"testing"
)

func TestParseESM(t *testing.T) {
	cases := map[string][]string{
		"esm-infra\nesm-apps\nend\n": {"esm-infra", "esm-apps"},
		"end\n":                      {},
		"esm-infra\n":                nil, // cut short
		"":                           nil,
	}
	for in, want := range cases {
		if got := parseESM(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseESM(%q) = %#v, want %#v", in, got, want)
		}
	}
}

func TestParseKeyValues(t *testing.T) {
	got := parseKeyValues("periodic.Unattended-Upgrade=1\nunit.apt-daily-upgrade.timer=enabled\nend\n")
	want := map[string]string{"periodic.Unattended-Upgrade": "1", "unit.apt-daily-upgrade.timer": "enabled"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if parseKeyValues("unit.x=enabled\n") != nil {
		t.Error("output without end should count as incomplete")
	}
}
