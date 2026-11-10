package checks

import (
	"net"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

var hostBasedLogin = Check{
	ID:    "SSH-006",
	Title: "Host-based SSH login (.rhosts, hosts.equiv)",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.HostTrust == nil {
			return nil, unavailable(f, "rhosts", "host-based trust files")
		}
		if f.NoSSHD() || len(f.HostTrust) == 0 {
			return nil, ""
		}
		if f.SSHD == nil {
			return nil, "sshd's configuration unavailable: " + f.Errors["sshd"]
		}
		on := func(cfg map[string][]string, k string) bool { return len(cfg[k]) > 0 && cfg[k][0] == "yes" }
		// honored says whether sshd, with this config, lets an entry in:
		// host-based authentication on, and a host it can match (with
		// UseDNS no, the default, only addresses and netgroups match: a
		// name never did in the lab).
		honored := func(cfg map[string][]string, t collect.HostTrust) bool {
			if cfg == nil || !on(cfg, "hostbasedauthentication") {
				return false
			}
			if t.Account != "" && !(len(cfg["ignorerhosts"]) > 0 && cfg["ignorerhosts"][0] == "no") {
				return false // IgnoreRhosts (on by default) skips ~/.rhosts and ~/.shosts
			}
			return strings.HasPrefix(t.Host, "+@") || net.ParseIP(t.Host) != nil ||
				on(cfg, "usedns") || on(cfg, "hostbasedusesnamefrompacketonly")
		}
		anyView := func(user string, t collect.HostTrust, root bool) bool {
			for _, v := range f.SSHDViews(user) {
				if root && len(v.Config["permitrootlogin"]) > 0 && v.Config["permitrootlogin"][0] == "no" {
					continue
				}
				if honored(v.Config, t) {
					return true
				}
			}
			return false
		}
		var rootFrom, anyUserFrom, sameUserFrom, accountFrom []string
		for _, t := range f.HostTrust {
			from := t.Host
			if t.User != "" {
				from = t.User + "@" + t.Host
			}
			switch {
			case t.Account == "root":
				if anyView("root", t, true) {
					rootFrom = append(rootFrom, from+" ("+t.File+")")
				}
			case t.Account != "":
				if anyView(t.Account, t, false) {
					accountFrom = append(accountFrom, t.Account+" from "+from+" ("+t.File+")")
				}
			case anyView("", t, false):
				// The equiv files never count for root. Naming a remote
				// user lets that user in as any account.
				if t.User != "" {
					anyUserFrom = append(anyUserFrom, from+" ("+t.File+")")
				} else {
					sameUserFrom = append(sameUserFrom, from+" ("+t.File+")")
				}
			}
		}
		var out []Finding
		if len(rootFrom) > 0 {
			out = append(out, Finding{CheckID: "SSH-006", Severity: High,
				Title:  "root can log in over SSH from other hosts without a key or password",
				Detail: "host-based login trusts " + strings.Join(rootFrom, ", ") + ": whoever is root on those hosts, or has their host key, is root here",
				Fix:    "Remove /root/.rhosts and /root/.shosts, and set IgnoreRhosts yes (the default) or HostbasedAuthentication no in sshd_config"})
		}
		if len(anyUserFrom) > 0 {
			out = append(out, Finding{CheckID: "SSH-006", Severity: High,
				Title:  "Remote accounts can log in over SSH as any account but root, without a key or password",
				Detail: "an equiv file names a remote user (" + strings.Join(anyUserFrom, ", ") + "), which lets that user in as every local account except root",
				Fix:    "Remove the user names from /etc/hosts.equiv and /etc/ssh/shosts.equiv, or set HostbasedAuthentication no in sshd_config"})
		}
		if len(sameUserFrom)+len(accountFrom) > 0 {
			var detail []string
			if len(sameUserFrom) > 0 {
				detail = append(detail, "an account of the same name on "+strings.Join(sameUserFrom, ", ")+" logs in as that account here (every account but root)")
			}
			if len(accountFrom) > 0 {
				detail = append(detail, "accounts' own trust files: "+summarize(accountFrom, 5))
			}
			out = append(out, Finding{CheckID: "SSH-006", Severity: Medium,
				Title:  "Accounts can log in over SSH from other hosts without a key or password",
				Detail: strings.Join(detail, "; ") + "; whoever is root on those hosts can log in as them",
				Fix:    "Use SSH keys instead: set HostbasedAuthentication no in sshd_config and remove the trust files, or keep the list to hosts you administer as tightly as this one"})
		}
		return out, ""
	},
}
