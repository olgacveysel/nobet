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
