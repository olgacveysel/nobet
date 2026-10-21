// Package buildinfo says which version a binary is.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Version returns set, the version given at build time (-ldflags
// "-X main.version=0.1.0", as releases, the Makefile and the Dockerfile do),
// or when none was given ("dev"), the module version the go command recorded:
// 0.1.0 for `go install github.com/olgacveysel/nobet/cmd/nobet@v0.1.0`.
func Version(set string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return set
	}
	return choose(set, bi.Main.Version)
}

func choose(set, module string) string {
	if set != "dev" || module == "" || module == "(devel)" {
		return set
	}
	return strings.TrimPrefix(module, "v")
}
