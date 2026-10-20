package checks

import (
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// weakAlgorithms are algorithms sshd should no longer offer, by sshd -T
// keyword: Medium for broken or far too weak ones (RC4, 3DES, MD5, 1024-bit
// DH, DSA), Low for deprecated ones (CBC modes, SHA-1 signatures and key
// exchange). Plain hmac-sha1 and umac-64 stay out: they are in OpenSSH's
// own defaults and not broken as MACs.
var weakAlgorithms = map[string]map[string]Severity{
	"ciphers": {
		"3des-cbc": Medium, "blowfish-cbc": Medium, "cast128-cbc": Medium,
		"arcfour": Medium, "arcfour128": Medium, "arcfour256": Medium,
		"aes128-cbc": Low, "aes192-cbc": Low, "aes256-cbc": Low, "rijndael-cbc@lysator.liu.se": Low,
	},
	"macs": {
		"hmac-md5": Medium, "hmac-md5-96": Medium, "hmac-md5-etm@openssh.com": Medium, "hmac-md5-96-etm@openssh.com": Medium,
		"hmac-sha1-96": Low, "hmac-sha1-96-etm@openssh.com": Low,
		"hmac-ripemd160": Low, "hmac-ripemd160@openssh.com": Low, "hmac-ripemd160-etm@openssh.com": Low,
	},
	"kexalgorithms": {
		"diffie-hellman-group1-sha1":  Medium,
		"diffie-hellman-group14-sha1": Low, "diffie-hellman-group-exchange-sha1": Low,
	},
	"hostkeyalgorithms": {
		"ssh-dss": Medium, "ssh-dss-cert-v01@openssh.com": Medium,
		"ssh-rsa": Low, "ssh-rsa-cert-v01@openssh.com": Low,
	},
	"pubkeyacceptedalgorithms": {
		"ssh-dss": Medium, "ssh-dss-cert-v01@openssh.com": Medium,
		"ssh-rsa": Low, "ssh-rsa-cert-v01@openssh.com": Low,
	},
}

// algorithmKinds names sshd -T keywords for people, in report order.
// OpenSSH before 8.5 calls pubkeyacceptedalgorithms pubkeyacceptedkeytypes.
var algorithmKinds = []struct{ keyword, alias, name string }{
	{"ciphers", "", "ciphers"},
	{"macs", "", "MACs"},
	{"kexalgorithms", "", "key exchange"},
	{"hostkeyalgorithms", "", "host key signatures"},
	{"pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "user key signatures"},
}

var sshWeakAlgorithms = Check{
	ID:    "SSH-005",
	Title: "Weak SSH algorithms",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if skip := sshdSkip(f); skip != "" {
			return nil, skip
		}
		// Match blocks cannot change these keywords, so the global
		// config is the whole story.
		sev := Severity(-1)
		var parts []string
		for _, k := range algorithmKinds {
			v := collect.SSHDFirst(f.SSHD, k.keyword)
			if v == "" && k.alias != "" {
				v = collect.SSHDFirst(f.SSHD, k.alias)
			}
			var weak []string
			for _, a := range strings.Split(v, ",") {
				if s, ok := weakAlgorithms[k.keyword][strings.TrimSpace(a)]; ok {
					weak = append(weak, a)
					if s > sev {
						sev = s
					}
				}
			}
			if len(weak) > 0 {
				parts = append(parts, k.name+": "+strings.Join(weak, ", "))
			}
		}
		if len(parts) == 0 {
			return nil, ""
		}
		title := "SSH server offers deprecated algorithms"
		if sev == Medium {
			title = "SSH server offers weak algorithms"
		}
		fix := "Remove them from Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms and PubkeyAcceptedAlgorithms in sshd_config (a leading - removes from the defaults, e.g. Ciphers -*-cbc)"
		switch f.OSRelease["ID"] {
		case "rhel", "centos", "rocky", "almalinux", "ol", "fedora":
			fix = "These come from the system crypto policy: update-crypto-policies --set DEFAULT:NO-SHA1 (or FUTURE), then restart sshd; or override the keywords in sshd_config"
		}
		return []Finding{{
			CheckID:  "SSH-005",
			Severity: sev,
			Title:    title,
			Detail:   strings.Join(parts, "; "),
			Fix:      fix,
		}}, ""
	},
}

// sshdSkip returns why the sshd checks cannot run, or "" if they can.
func sshdSkip(f *collect.Facts) string {
	switch {
	case f.NoSSHD():
		return "sshd is not installed"
	case f.SSHD != nil:
		return ""
	case !f.Privileged():
		return "effective sshd config unavailable (needs root or passwordless sudo)"
	case f.Errors["sshd"] != "":
		return "sshd -T failed: " + f.Errors["sshd"]
	}
	return "effective sshd config unavailable"
}

// sshdWorst rates every sshd view of users (each from anywhere and from
// every address range Match blocks name) and returns the worst rating,
// the first view that has it, and where it applies. where is "" when the
// first user's view from anywhere has it, so the setting is effectively
// global; otherwise it lists the users and addresses it applies to.
func sshdWorst(f *collect.Facts, users []string, rate func(v collect.SSHDView) int) (rating int, view collect.SSHDView, where string) {
	rating = -1
	var hits []collect.SSHDView
	for _, u := range users {
		for _, v := range f.SSHDViews(u) {
			r := rate(v)
			if r > rating {
				rating, view, hits = r, v, nil
			}
			if r == rating {
				hits = append(hits, v)
			}
		}
	}
	// An account that has the setting from anywhere needs no address list.
	anywhere := map[string]bool{}
	for _, v := range hits {
		if v.From == "" {
			anywhere[v.User] = true
		}
	}
	if anywhere[users[0]] {
		return rating, view, ""
	}
	var places []string
	for _, v := range hits {
		if v.From != "" && anywhere[v.User] {
			continue
		}
		if p := place(v, len(users) > 1); !contains(places, p) {
			places = append(places, p)
		}
	}
	return rating, view, summarize(places, 4)
}

// place describes the account and address an sshd view is for.
func place(v collect.SSHDView, withUser bool) string {
	var parts []string
	if withUser && v.User != "" {
		parts = append(parts, "for "+v.User)
	}
	if v.From != "" {
		parts = append(parts, "from "+v.From)
	}
	if len(parts) == 0 {
		return "for any account"
	}
	return strings.Join(parts, " ")
}

// scoped appends where a setting applies to a finding's detail.
func scoped(detail, where string) string {
	if where == "" {
		return detail
	}
	return detail + " (set by Match blocks: " + where + ")"
}

// uid0Users lists the accounts PermitRootLogin applies to.
func uid0Users(f *collect.Facts) []string {
	var out []string
	for _, p := range f.Passwd {
		if p.UID == 0 {
			out = append(out, p.Name)
		}
	}
	if len(out) == 0 {
		out = []string{"root"}
	}
	return out
}

var sshRootLogin = Check{
	ID:    "SSH-001",
	Title: "Direct root login over SSH",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if skip := sshdSkip(f); skip != "" {
			return nil, skip
		}
		rating, v, where := sshdWorst(f, uid0Users(f), func(v collect.SSHDView) int {
			if !f.LoginAllowed(v.Config, v.User) {
				return 0
			}
			switch collect.SSHDFirst(v.Config, "permitrootlogin") {
			case "yes":
				return 2
			case "prohibit-password", "without-password", "forced-commands-only":
				return 1
			}
			return 0
		})
		value := collect.SSHDFirst(v.Config, "permitrootlogin")
		switch rating {
		case 2:
			return []Finding{{
				CheckID:  "SSH-001",
				Severity: High,
				Title:    "Root can log in directly over SSH",
				Detail:   scoped("PermitRootLogin yes", where),
				Fix:      "Set 'PermitRootLogin no' in sshd_config, use named accounts with sudo, then reload sshd",
			}}, ""
		case 1:
			return []Finding{{
				CheckID:  "SSH-001",
				Severity: Low,
				Title:    "Root can log in over SSH with a key",
				Detail:   scoped("PermitRootLogin "+value, where),
				Fix:      "Prefer 'PermitRootLogin no' so every action is tied to a named account",
			}}, ""
		}
		return nil, ""
	},
}

var sshPasswordAuth = Check{
	ID:    "SSH-002",
	Title: "Password authentication",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if skip := sshdSkip(f); skip != "" {
			return nil, skip
		}
		rating, _, where := sshdWorst(f, f.SSHDUsers(), func(v collect.SSHDView) int {
			if collect.SSHDFirst(v.Config, "passwordauthentication") == "yes" {
				return 2
			}
			kbd := collect.SSHDFirst(v.Config, "kbdinteractiveauthentication")
			if kbd == "" {
				kbd = collect.SSHDFirst(v.Config, "challengeresponseauthentication") // OpenSSH < 8.7
			}
			if kbd == "yes" && collect.SSHDFirst(v.Config, "usepam") == "yes" {
				return 1
			}
			return 0
		})
		switch rating {
		case 2:
			return []Finding{{
				CheckID:  "SSH-002",
				Severity: Medium,
				Title:    "SSH password authentication is enabled",
				Detail:   scoped("PasswordAuthentication yes exposes the host to password guessing", where),
				Fix:      "Set 'PasswordAuthentication no' after confirming key-based access works",
			}}, ""
		case 1:
			return []Finding{{
				CheckID:  "SSH-002",
				Severity: Low,
				Title:    "Keyboard-interactive auth via PAM may still accept passwords",
				Detail:   scoped("KbdInteractiveAuthentication yes with UsePAM yes", where),
				Fix:      "Set 'KbdInteractiveAuthentication no' unless you use PAM-based MFA",
			}}, ""
		}
		return nil, ""
	},
}

var sshEmptyPasswords = Check{
	ID:    "SSH-003",
	Title: "Empty passwords over SSH",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if skip := sshdSkip(f); skip != "" {
			return nil, skip
		}
		rating, _, where := sshdWorst(f, f.SSHDUsers(), func(v collect.SSHDView) int {
			if collect.SSHDFirst(v.Config, "permitemptypasswords") == "yes" {
				return 1
			}
			return 0
		})
		if rating < 1 {
			return nil, ""
		}
		return []Finding{{
			CheckID:  "SSH-003",
			Severity: Critical,
			Title:    "SSH accepts logins with empty passwords",
			Detail:   scoped("PermitEmptyPasswords yes", where),
			Fix:      "Set 'PermitEmptyPasswords no' and reload sshd",
		}}, ""
	},
}

var sshX11Forwarding = Check{
	ID:    "SSH-004",
	Title: "X11 forwarding",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if skip := sshdSkip(f); skip != "" {
			return nil, skip
		}
		rating, _, where := sshdWorst(f, f.SSHDUsers(), func(v collect.SSHDView) int {
			if collect.SSHDFirst(v.Config, "x11forwarding") == "yes" {
				return 1
			}
			return 0
		})
		if rating < 1 {
			return nil, ""
		}
		return []Finding{{
			CheckID:  "SSH-004",
			Severity: Low,
			Title:    "X11 forwarding is enabled",
			Detail:   scoped("X11Forwarding yes; servers rarely need it", where),
			Fix:      "Set 'X11Forwarding no' unless users run graphical apps over SSH",
		}}, ""
	},
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
