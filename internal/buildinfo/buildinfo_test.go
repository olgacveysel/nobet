package buildinfo

import "testing"

func TestChoose(t *testing.T) {
	cases := []struct{ set, module, want string }{
		{"0.1.0", "v0.1.0", "0.1.0"},          // release build: -ldflags wins
		{"0.2.0~rc1", "(devel)", "0.2.0~rc1"}, // goreleaser in a checkout
		{"dev", "v0.1.0", "0.1.0"},            // go install ...@v0.1.0
		{"dev", "v0.1.1-0.20261021134900-8b81fbd3061a+dirty", "0.1.1-0.20261021134900-8b81fbd3061a+dirty"},
		{"dev", "(devel)", "dev"}, // no version information
		{"dev", "", "dev"},
	}
	for _, c := range cases {
		if got := choose(c.set, c.module); got != c.want {
			t.Errorf("choose(%q, %q) = %q, want %q", c.set, c.module, got, c.want)
		}
	}
}
