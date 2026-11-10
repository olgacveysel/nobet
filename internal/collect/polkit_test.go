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

// Debian 13's and AlmaLinux 9's own rules (polkit 126 and 0.117), and the
// shapes rules that hand out root take.
const (
	debianNetworkd = `polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.hostname1.set-hostname" ||
         action.id == "org.freedesktop.hostname1.get-product-uuid" ||
         action.id == "org.freedesktop.timedate1.set-timezone") &&
        subject.user == "systemd-network") {
        return polkit.Result.YES;
    }
});
`
	debianDefault = `/* -*- mode: js; js-indent-level: 4; indent-tabs-mode: nil -*- */
polkit.addAdminRule(function(action, subject) {
    return ["unix-group:sudo"];
});
`
	almaCompat = `polkit.addRule(function(action, subject) {
	var params = ['/usr/bin/pkla-check-authorization',
		      subject.user, subject.local ? 'true' : 'false',
		      subject.active ? 'true' : 'false', action.id];
	var res = polkit.spawn(params);
	if (res == '')
		return null;
	return res.replace(/\n$/, '');
});
`
	labRules = `// Let alice use pkexec.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" && subject.user == "alice") {
        return polkit.Result.YES;
    }
});
/* Ops may manage services (and anything else under systemd1). */
polkit.addRule(function(action, subject) {
    if (action.id.startsWith('org.freedesktop.systemd1.') && subject.isInGroup("ops")) {
        return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
    var allowed = ["org.freedesktop.packagekit.package-install-untrusted",
                   "org.freedesktop.accounts.user-administration"];
    if (allowed.indexOf(action.id) >= 0 && subject.isInGroup("desk")) {
        return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) { return polkit.Result.YES; });
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.login1.reboot") { return polkit.Result.AUTH_ADMIN; }
});
`
	labPKLA = `[Let devs restart services]
Identity=unix-group:devs;unix-user:bob
Action=org.freedesktop.systemd1.*
ResultAny=no
ResultInactive=no
ResultActive=yes

[Read-only]
Identity=unix-user:*
Action=org.freedesktop.login1.*
ResultAny=auth_admin
`
)

func TestPolkitScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	put := func(p, content string) {
		t.Helper()
		p = filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("usr/share/polkit-1/rules.d/systemd-networkd.rules", debianNetworkd)
	put("usr/share/polkit-1/rules.d/50-default.rules", debianDefault)
	put("etc/polkit-1/rules.d/49-polkit-pkla-compat.rules", almaCompat)
	put("etc/polkit-1/rules.d/10-lab.rules", labRules)
	put("etc/polkit-1/localauthority/50-local.d/lab.pkla", labPKLA)
	bin := filepath.Join(dir, "bin")
	put("bin/pkexec", "#!/bin/sh\necho 'pkexec version 126'\n")
	os.Chmod(filepath.Join(bin, "pkexec"), 0o755)

	run := func(path string) (*Polkit, string) {
		t.Helper()
		script := strings.NewReplacer("/etc/polkit-1", dir+"/etc/polkit-1", "/usr/share/polkit-1", dir+"/usr/share/polkit-1",
			"/run/polkit-1", dir+"/run/polkit-1", "/usr/local/share/polkit-1", dir+"/usr/local/share/polkit-1",
			"/var/lib/polkit-1", dir+"/var/lib/polkit-1", "/usr/bin/pkla-check-authorization", dir+"/bin/pkla-check-authorization").Replace(polkitScript)
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+path)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return parsePolkit(string(out))
	}
	got, why := run(bin + ":/usr/bin:/bin")
	lab := dir + "/etc/polkit-1/rules.d/10-lab.rules"
	want := &Polkit{Version: "126", JSRules: true, Rules: []PolkitRule{
		{File: lab, Yes: true, ActionCheck: true, Actions: []string{"org.freedesktop.policykit.exec"}, Users: []string{"alice"}},
		{File: lab, Yes: true, ActionCheck: true, Prefixes: []string{"org.freedesktop.systemd1."}, Groups: []string{"ops"}},
		{File: lab, Yes: true, ActionCheck: true, Actions: []string{"org.freedesktop.packagekit.package-install-untrusted", "org.freedesktop.accounts.user-administration"}, Groups: []string{"desk"}},
		{File: lab, Yes: true},
		{File: dir + "/usr/share/polkit-1/rules.d/systemd-networkd.rules", Yes: true, ActionCheck: true,
			Actions: []string{"org.freedesktop.hostname1.set-hostname", "org.freedesktop.hostname1.get-product-uuid", "org.freedesktop.timedate1.set-timezone"},
			Users:   []string{"systemd-network"}},
	}, Grants: []PKLAGrant{{File: dir + "/etc/polkit-1/localauthority/50-local.d/lab.pkla",
		Identities: []string{"unix-group:devs", "unix-user:bob"}, Actions: []string{"org.freedesktop.systemd1.*"}}}}
	if why != "" || !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v (%q)\nwant %+v", got, why, want)
	}

	// polkit 0.105 (Ubuntu 22.04) ignores JavaScript rules and reads .pkla.
	put("bin/pkexec", "#!/bin/sh\necho 'pkexec version 0.105'\n")
	if got, _ := run(bin + ":/usr/bin:/bin"); got == nil || got.JSRules || !got.PKLA {
		t.Errorf("0.105: %+v", got)
	}
	// pkla-compat makes later versions read .pkla too.
	put("bin/pkexec", "#!/bin/sh\necho 'pkexec version 0.117'\n")
	put("bin/pkla-check-authorization", "#!/bin/sh\n")
	os.Chmod(filepath.Join(bin, "pkla-check-authorization"), 0o755)
	if got, _ := run(bin + ":/usr/bin:/bin"); got == nil || !got.JSRules || !got.PKLA {
		t.Errorf("0.117 with pkla-compat: %+v", got)
	}
	// No polkit at all.
	os.RemoveAll(filepath.Join(dir, "etc"))
	os.RemoveAll(filepath.Join(dir, "usr"))
	os.Remove(filepath.Join(bin, "pkexec"))
	if got, why := run(bin); got == nil || got.Version != "" || why != "" {
		t.Errorf("no polkit: %+v %q", got, why)
	}
}

func TestLegacyPolkit(t *testing.T) {
	for v, want := range map[string]bool{"0.105": true, "0.105-33": true, "0.96": true, "0.106": false, "0.117": false, "0.120-1": false, "126": false, "126-2": false, "unknown": false} {
		if got := legacyPolkit(v); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
}
