package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestShadowScript runs the real collector script against a sample shadow
// file, covering the formats seen on Debian, RHEL, CentOS 7 and Alpine.
func TestShadowScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	sample := strings.Join([]string{
		`root:$y$j9T$abc$def:19000:0:99999:7:::`,      // yescrypt
		`admin:$6$salt$hash:19000:0:99999:7:::`,       // sha512
		`old:abcdefghijklm:19000:0:99999:7:::`,        // DES
		`locked:!$6$salt$hash:19000:0:99999:7:::`,     // usermod -L
		`never:!!:19000:0:99999:7:::`,                 // RHEL: never set
		`system:*:19000:0:99999:7:::`,                 // no password
		`centos:locked::0:99999:7:::`,                 // CentOS 7 image placeholder
		`guest::19000:0:99999:7:::`,                   // empty
		`gone:$6$salt$hash:19000:0:99999:7::1:`,       // expired in 1970
		`future:$6$salt$hash:19000:0:99999:7::99999:`, // expires in 2243
		`zero:$6$salt$hash:19000:0:99999:7::0:`,       // 0: treated as no expiry
	}, "\n") + "\n"
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", strings.ReplaceAll(shadowScript, "/etc/shadow", path)).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := []ShadowEntry{
		{User: "root", Password: PasswordSet},
		{User: "admin", Password: PasswordSet},
		{User: "old", Password: PasswordSet},
		{User: "locked", Password: PasswordLocked},
		{User: "never", Password: PasswordLocked},
		{User: "system", Password: PasswordLocked},
		{User: "centos", Password: PasswordLocked},
		{User: "guest", Password: PasswordEmpty},
		{User: "gone", Password: PasswordSet, Expired: true},
		{User: "future", Password: PasswordSet},
		{User: "zero", Password: PasswordSet},
	}
	got := parseShadow(string(out))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v\nraw output:\n%s", got, want, out)
	}
	if strings.Contains(string(out), "$") {
		t.Errorf("password hashes must never be printed:\n%s", out)
	}
}

func TestPassword(t *testing.T) {
	f := &Facts{Shadow: []ShadowEntry{{User: "alice", Password: PasswordEmpty, Expired: true}}}
	if pw, exp, ok := f.Password("alice"); pw != PasswordEmpty || !exp || !ok {
		t.Errorf("alice: %q %v %v", pw, exp, ok)
	}
	if _, _, ok := f.Password("bob"); ok {
		t.Error("bob is not in shadow")
	}
}
