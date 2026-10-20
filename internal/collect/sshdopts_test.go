package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sshd_opts_from runs for real on command lines as /proc shows them.
func TestSSHDOptsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	cases := map[string]string{
		// Rocky 8: systemd starts sshd -D $OPTIONS $CRYPTO_POLICY; argv is NUL-separated.
		"rhel8": "/usr/sbin/sshd\x00-D\x00-oCiphers=aes256-gcm@openssh.com,aes256-ctr\x00-oMACs=hmac-sha2-256-etm@openssh.com\x00-oKexAlgorithms=curve25519-sha256\x00",
		// OpenSSH 9 listener: the process title is one string.
		"ubuntu": "sshd: /usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com [listener] 0 of 10-100 startups\x00",
		// -o and its value as two arguments; -D, -p and -f are not passed on.
		"split": "/usr/sbin/sshd\x00-o\x00PermitRootLogin=no\x00-p\x002222\x00-f\x00/etc/ssh/alt\x00",
		"none":  "/usr/sbin/sshd\x00-D\x00",
	}
	want := map[string]string{
		"rhel8":  "-oCiphers=aes256-gcm@openssh.com,aes256-ctr\n-oMACs=hmac-sha2-256-etm@openssh.com\n-oKexAlgorithms=curve25519-sha256\n",
		"ubuntu": "-oCiphers=aes256-gcm@openssh.com\n",
		"split":  "-oPermitRootLogin=no\n",
		"none":   "",
	}
	dir := t.TempDir()
	for name, cmdline := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(cmdline), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("/bin/sh", "-c", sshdOptsFunc+`sshd_opts_from "$1"`, "sh", p).Output()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(out) != want[name] {
			t.Errorf("%s: got %q, want %q", name, out, want[name])
		}
	}
}

// Every script that runs sshd -T passes the running daemon's options.
func TestScriptsPassSSHDOpts(t *testing.T) {
	for name, s := range map[string]string{"sshd": sshdScript, "authkeys": authKeysScript, "match": sshdMatchScript([]string{"deploy"}, nil, 22)} {
		if !strings.Contains(s, "sshd_opts()") {
			t.Errorf("%s script does not define sshd_opts", name)
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "sshd -T") && !strings.Contains(line, "opts") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				t.Errorf("%s script runs sshd -T without the options: %s", name, line)
			}
		}
	}
}
