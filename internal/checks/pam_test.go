package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func pl(typ, control, module string, args ...string) collect.PAMLine {
	return collect.PAMLine{Type: typ, Control: control, Module: module, Args: args}
}

// The auth stacks of Debian 13 and AlmaLinux 9 as shipped (testdata/pam in
// collect), which a wrong password does not get through.
func debianPAM() map[string][]collect.PAMLine {
	return map[string][]collect.PAMLine{
		"common-auth": {pl("auth", "[success=1 default=ignore]", "pam_unix.so"), pl("auth", "requisite", "pam_deny.so"), pl("auth", "required", "pam_permit.so")},
		"su":          {pl("auth", "sufficient", "pam_rootok.so"), pl("@include", "", "common-auth")},
		"su-l":        {pl("auth", "include", "su")},
		"sudo":        {pl("@include", "", "common-auth")},
		"sshd":        {pl("@include", "", "common-auth")},
		"login":       {pl("auth", "optional", "pam_faildelay.so"), pl("auth", "requisite", "pam_nologin.so"), pl("@include", "", "common-auth")},
	}
}

func almaPAM() map[string][]collect.PAMLine {
	auth := []collect.PAMLine{pl("auth", "required", "pam_env.so"), pl("auth", "required", "pam_faillock.so", "preauth", "silent"),
		pl("auth", "sufficient", "pam_unix.so"), pl("auth", "[default=die]", "pam_faillock.so", "authfail"), pl("auth", "required", "pam_deny.so")}
	return map[string][]collect.PAMLine{
		"system-auth": auth, "password-auth": auth, "postlogin": {},
		"su":   {pl("auth", "required", "pam_env.so"), pl("auth", "sufficient", "pam_rootok.so"), pl("auth", "substack", "system-auth"), pl("auth", "include", "postlogin")},
		"sudo": {pl("auth", "include", "system-auth")},
		"sshd": {pl("auth", "substack", "password-auth"), pl("auth", "include", "postlogin")},
	}
}

func TestPAMBypass(t *testing.T) {
	run := func(pam map[string][]collect.PAMLine, sshd map[string][]string) []Finding {
		t.Helper()
		f := &collect.Facts{Errors: map[string]string{}, PAM: pam, SSHD: sshd,
			Groups: []collect.GroupEntry{{Name: "wheel", GID: 10, Members: []string{"alice"}}}}
		got, skip := pamBypass.Run(f)
		if skip != "" {
			t.Fatal(skip)
		}
		return got
	}
	if got := run(debianPAM(), nil); len(got) != 0 {
		t.Errorf("Debian as shipped: %+v", got)
	}
	if got := run(almaPAM(), nil); len(got) != 0 {
		t.Errorf("Alma as shipped: %+v", got)
	}

	// A sufficient pam_permit in front of su.
	p := debianPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "sufficient", "pam_permit.so")}, p["su"]...)
	if got := run(p, nil); len(got) != 1 || got[0].Severity != Critical || got[0].Title != "PAM accepts any password for su, su-l" ||
		!strings.Contains(got[0].Detail, "pam_permit.so in /etc/pam.d/su") {
		t.Errorf("pam_permit in su: %+v", got)
	}

	// common-auth with pam_deny made optional: a wrong password falls
	// through to the final pam_permit, for everything that includes it.
	p = debianPAM()
	p["common-auth"][1].Control = "optional"
	got := run(p, nil)
	if len(got) != 1 || got[0].Title != "PAM accepts any password for su, su-l, sudo, sshd, login" ||
		!strings.Contains(got[0].Detail, "pam_permit.so in /etc/pam.d/common-auth") {
		t.Errorf("optional pam_deny: %+v", got)
	}
	// sshd only uses PAM for passwords when it asks for one.
	keyOnly := map[string][]string{"usepam": {"yes"}, "passwordauthentication": {"no"}, "kbdinteractiveauthentication": {"no"}}
	if got := run(p, keyOnly); len(got) != 1 || strings.Contains(got[0].Title, "sshd") {
		t.Errorf("key-only sshd: %+v", got)
	}

	// The backdoor in a substack (Alma's su uses system-auth that way).
	p = almaPAM()
	p["system-auth"] = append([]collect.PAMLine{pl("auth", "sufficient", "pam_permit.so")}, p["system-auth"]...)
	if got := run(p, nil); len(got) != 1 || got[0].Title != "PAM accepts any password for su, sudo" {
		t.Errorf("pam_permit in system-auth: %+v", got)
	}

	// pam_wheel trust: wheel's members su without a password.
	p = almaPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "sufficient", "pam_wheel.so", "trust", "use_uid")}, p["su"]...)
	got = run(p, nil)
	if len(got) != 1 || got[0].Severity != High || !strings.Contains(got[0].Detail, "members of wheel (alice)") ||
		!strings.Contains(got[0].Fix, "trust") {
		t.Errorf("pam_wheel trust: %+v", got)
	}
	// Without trust it only limits su to wheel: fine.
	p = almaPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "required", "pam_wheel.so", "use_uid")}, p["su"]...)
	if got := run(p, nil); len(got) != 0 {
		t.Errorf("pam_wheel without trust: %+v", got)
	}

	// trust after required does not skip the password: pam_unix decides.
	p = almaPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "required", "pam_wheel.so", "trust", "use_uid")}, p["su"]...)
	if got := run(p, nil); len(got) != 0 {
		t.Errorf("required pam_wheel trust: %+v", got)
	}
	// Without a wheel group, pam_wheel uses the group with GID 0.
	p = debianPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "sufficient", "pam_wheel.so", "trust")}, p["su"]...)
	f := &collect.Facts{Errors: map[string]string{}, PAM: p,
		Groups: []collect.GroupEntry{{Name: "root", GID: 0, Members: []string{"carol"}}, {Name: "sudo", GID: 27}}}
	if got, _ := pamBypass.Run(f); len(got) != 1 || !strings.Contains(got[0].Detail, "members of root (carol)") {
		t.Errorf("pam_wheel trust, no wheel group: %+v", got)
	}
	// deny inverts pam_wheel: everyone outside the group passes.
	p = debianPAM()
	p["su"] = append([]collect.PAMLine{pl("auth", "sufficient", "pam_wheel.so", "deny", "group=nosu")}, p["su"]...)
	if got := run(p, nil); len(got) != 1 || got[0].Severity != Critical {
		t.Errorf("pam_wheel deny: %+v", got)
	}
	// A Match block that turns passwords on for some addresses counts.
	p = debianPAM()
	p["common-auth"][1].Control = "optional"
	f = &collect.Facts{Errors: map[string]string{}, PAM: p, SSHD: keyOnly,
		SSHDMatch: []collect.SSHDContext{{Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{"passwordauthentication": {"yes"}}}}}
	if got, _ := pamBypass.Run(f); len(got) != 1 || !strings.Contains(got[0].Title, "sshd") {
		t.Errorf("Match enables passwords: %+v", got)
	}

	f = &collect.Facts{Errors: map[string]string{"pam": "cannot read /etc/pam.d/su"}}
	if _, skip := pamBypass.Run(f); !strings.Contains(skip, "cannot read") {
		t.Errorf("unreadable: %q", skip)
	}
}

func TestPAMAction(t *testing.T) {
	for _, c := range []struct{ control, result, want string }{
		{"required", pamFail, "bad"}, {"required", pamIgnore, "ignore"}, {"requisite", pamFail, "die"},
		{"sufficient", pamSuccess, "done"}, {"sufficient", pamFail, "ignore"}, {"optional", pamFail, "ignore"},
		{"[success=1 default=ignore]", pamSuccess, "1"}, {"[success=1 default=ignore]", pamFail, "ignore"},
		{"[default=die]", pamFail, "die"}, {"[success=ok]", pamFail, "bad"},
	} {
		if got := pamAction(c.control, c.result); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.control, c.result, got, c.want)
		}
	}
}
