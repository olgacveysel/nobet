package collect

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/runner"
)

// fakeRunner answers commands from a table. Collector scripts are decoded
// first, so the table can be keyed by script body; viaSudo records which
// scripts were piped to sudo.
type fakeRunner struct {
	out     map[string]runner.Result
	viaSudo map[string]bool
}

func (r *fakeRunner) Run(cmd string) (runner.Result, error) {
	if rest, ok := strings.CutPrefix(cmd, "echo "); ok {
		b64, pipe, _ := strings.Cut(rest, " | base64 -d | ")
		body, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return runner.Result{}, err
		}
		if pipe == "sudo -n sh" {
			r.viaSudo[string(body)] = true
		}
		cmd = string(body)
	}
	if res, ok := r.out[cmd]; ok {
		return res, nil
	}
	return runner.Result{ExitCode: 127, Stderr: "not found"}, nil
}

func newFake(out map[string]runner.Result) *fakeRunner {
	return &fakeRunner{out: out, viaSudo: map[string]bool{}}
}

func TestCollectUnprivileged(t *testing.T) {
	r := newFake(map[string]runner.Result{
		"id -u":           {Stdout: "1000\n"},
		"sudo -n true":    {ExitCode: 1, Stderr: "sudo: a password is required"},
		"cat /etc/passwd": {Stdout: "root:x:0:0:root:/root:/bin/bash\n"},
		"cat /etc/group":  {Stdout: "root:x:0:\n"},
		// The sudoers script succeeds even when nothing is readable.
		sudoersScript: {Stdout: ""},
	})
	f := Collect(r)
	if f.Privileged() {
		t.Fatal("should not be privileged")
	}
	if f.Sudoers != nil || f.AuthKeys != nil || f.SudoRights != nil || f.Firewall != nil || f.SUID != nil {
		t.Errorf("root-only data must stay nil without privilege: %+v", f)
	}
	for _, name := range []string{"sudoers", "authkeys", "sudo-rights", "firewall", "files"} {
		if f.Errors[name] == "" {
			t.Errorf("missing error for %s", name)
		}
	}
	if len(f.Passwd) != 1 || f.SSHD != nil {
		t.Errorf("passwd %+v, sshd %+v", f.Passwd, f.SSHD)
	}
}

func TestCollectSudo(t *testing.T) {
	r := newFake(map[string]runner.Result{
		"id -u":          {Stdout: "1000\n"},
		"sudo -n true":   {},
		sshdScript:       {}, // sshd not installed: no output, exit 0
		sudoersScript:    {Stdout: "/etc/sudoers: root ALL=(ALL:ALL) ALL\n"},
		authKeysScript:   {},
		sudoRightsScript: {},
	})
	f := Collect(r)
	if !f.SudoOK || !f.Privileged() {
		t.Fatal("passwordless sudo not detected")
	}
	if !f.NoSSHD() {
		t.Errorf("empty sshd output should mean no sshd, got %+v (err %q)", f.SSHD, f.Errors["sshd"])
	}
	if len(f.Sudoers) != 1 || f.AuthKeys == nil || len(f.AuthKeys) != 0 {
		t.Errorf("sudoers %+v, authkeys %+v", f.Sudoers, f.AuthKeys)
	}
	for _, s := range []string{sshdScript, sudoersScript, authKeysScript, sudoRightsScript} {
		if !r.viaSudo[s] {
			t.Errorf("script not run through sudo:\n%s", s)
		}
	}
	if r.viaSudo[listenersScript] {
		t.Error("listeners script needs no sudo")
	}
}
