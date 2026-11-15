package scan

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/runner"
)

// echoHost answers every command with the same text, as root: every
// collector runs, and every check sees what the parsers made of it.
type echoHost string

func (h echoHost) Run(cmd string) (runner.Result, error) {
	if cmd == "id -u" {
		return runner.Result{Stdout: "0\n"}, nil
	}
	return runner.Result{Stdout: string(h)}, nil
}

// FuzzEvaluate runs the whole scan, collectors and checks, against a host
// that says whatever the fuzzer likes. Nothing may panic. Run longer with
//
//	go test -run '^$' -fuzz FuzzEvaluate -fuzztime 2m ./internal/scan
func FuzzEvaluate(f *testing.F) {
	for _, s := range []string{
		"", "@@end\n", "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n@@end\n",
		"docker:x:999:alice\n@@user alice\n    (root) NOPASSWD: /usr/bin/find\n@@end\n",
		"door|docker|/run/docker.sock\nstat|0|999|666|socket|/run/docker.sock\nstat|0|0|755|directory|/run\nstat|0|0|755|directory|/\n@@end\n",
		"suid=none /tmp/x\nsuidmore=3\nww=d /etc/x\n@@end\n",
		"permitrootlogin yes\npasswordauthentication yes\nhostbasedauthentication yes\nignorerhosts no\n",
		"trust|/root/.shosts|root|10.0.0.1|root\n@@end\n",
		"cap=none|0|cap_setuid=ep|/usr/bin/python3.12\n@@end\n",
		"ID=debian\nVERSION_ID=13\nPRETTY_NAME=x\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if strings.Count(s, "\n") > 2000 {
			return // keep runs short; length is not what this looks for
		}
		var res HostResult
		Evaluate(&res, echoHost(s))
	})
}
