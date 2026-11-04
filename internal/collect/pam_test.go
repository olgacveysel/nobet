package collect

import (
	"embed"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// pamFiles are the stock /etc/pam.d of Debian 13 and AlmaLinux 9 (with
// sudo and openssh-server installed).
//
//go:embed testdata/pam
var pamFiles embed.FS

func TestPAMScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	for _, distro := range []string{"debian", "alma"} {
		dir := t.TempDir()
		sub, _ := fs.Sub(pamFiles, "testdata/pam/"+distro)
		fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := fs.ReadFile(sub, p)
				os.WriteFile(filepath.Join(dir, p), b, 0o644)
			}
			return err
		})
		// A module whose arguments hold a secret, a module path, a
		// continuation line and a module that may be missing (-auth).
		os.WriteFile(filepath.Join(dir, "custom"), []byte(
			"auth optional /usr/lib/security/pam_exec.so /usr/local/bin/notify --token=pamsecret\n"+
				"auth [success=done \\\n  default=ignore] pam_wheel.so trust group=admins # trusted\n"+
				"-auth sufficient pam_sss.so forward_pass\n"+
				"account required pam_unix.so\n"), 0o644)
		out, err := exec.Command("/bin/sh", "-c", strings.ReplaceAll(pamScript, "/etc/pam.d", dir)).Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "pamsecret") {
			t.Fatalf("%s: a module argument left the host:\n%s", distro, out)
		}
		got, why := parsePAM(string(out))
		if why != "" {
			t.Fatalf("%s: %s", distro, why)
		}
		want := map[string][]PAMLine{
			"debian": {{Type: "auth", Control: "sufficient", Module: "pam_rootok.so"}, {Type: "@include", Module: "common-auth"}},
			"alma": {{Type: "auth", Control: "required", Module: "pam_env.so"}, {Type: "auth", Control: "sufficient", Module: "pam_rootok.so"},
				{Type: "auth", Control: "substack", Module: "system-auth"}, {Type: "auth", Control: "include", Module: "postlogin"}},
		}[distro]
		// Debian's su names more includes (account, session): @include
		// takes every type, so they are kept.
		if distro == "debian" {
			want = append(want, PAMLine{Type: "@include", Module: "common-account"}, PAMLine{Type: "@include", Module: "common-session"})
		}
		if !reflect.DeepEqual(got["su"], want) {
			t.Errorf("%s su:\n got  %+v\n want %+v", distro, got["su"], want)
		}
		custom := []PAMLine{
			{Type: "auth", Control: "optional", Module: "pam_exec.so"},
			{Type: "auth", Control: "[success=done default=ignore]", Module: "pam_wheel.so", Args: []string{"trust", "group=admins"}},
			{Type: "auth", Control: "sufficient", Module: "pam_sss.so"},
		}
		if !reflect.DeepEqual(got["custom"], custom) {
			t.Errorf("%s custom:\n got  %+v\n want %+v", distro, got["custom"], custom)
		}
		if _, why := parsePAM(strings.TrimSuffix(string(out), "@@end\n")); why == "" {
			t.Error("output without @@end parsed")
		}
	}
	// No /etc/pam.d (busybox systems without PAM): nothing to check.
	out, _ := exec.Command("/bin/sh", "-c", strings.ReplaceAll(pamScript, "/etc/pam.d", t.TempDir()+"/none")).Output()
	if got, why := parsePAM(string(out)); got == nil || len(got) != 0 || why != "" {
		t.Errorf("no pam.d: %v %q", got, why)
	}
}
