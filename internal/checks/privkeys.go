package checks

import (
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

var readablePrivateKeys = Check{
	ID:    "FS-004",
	Title: "Private keys other accounts can read",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.PrivateKeys == nil {
			return nil, unavailable(f, "privkeys", "private key files")
		}
		// Keys that log in to an account that can become root here: reading
		// one is being root.
		rootKeys := map[string]string{}
		for _, ak := range f.AuthKeys {
			if _, ok := f.KeyLogin(ak.User); ok && canBecomeRoot(f, ak.User) && rootKeys[ak.Fingerprint] == "" {
				rootKeys[ak.Fingerprint] = ak.User
			}
		}
		var out []Finding
		for _, k := range f.PrivateKeys {
			who := "every account"
			switch {
			case k.Everyone:
			case k.Group != "":
				who = "the " + k.Group + " group (" + summarize(k.Readers, 4) + ")"
			default:
				who = summarize(k.Readers, 4)
			}
			sev := Medium
			if k.Everyone {
				sev = High
			}
			var notes []string
			if k.Fingerprint != "" {
				notes = append(notes, k.Fingerprint)
			}
			if u := rootKeys[k.Fingerprint]; u != "" && k.Kind == "ssh" {
				if uid0(f, u) {
					notes = append(notes, "it logs in as "+u+" on this host")
				} else {
					notes = append(notes, "it logs in as "+u+", who can become root on this host")
				}
				sev++ // High for named accounts, Critical for everyone
			}
			fnd := Finding{CheckID: "FS-004", Severity: sev}
			switch k.Kind {
			case "host":
				fnd.Title = "sshd's host key " + k.Path + " can be read by " + who
				notes = append(notes, "whoever has it can pose as this server")
				fnd.Fix = "chmod 600 " + k.Path + "; sshd refuses to load host keys others can read, so check which host keys it really uses, and replace this one if it may have been copied"
			case "tls":
				fnd.Title = "TLS private key " + k.Path + " can be read by " + who
				notes = append(notes, "whoever has it can pose as the sites it serves")
				fnd.Fix = "chmod 600 " + k.Path + " (or 640 with a group only the service is in); replace the key and certificate if it may have been copied"
			default:
				fnd.Title = "SSH private key " + k.Path + " can be read by " + who
				notes = append(notes, "whoever has it can log in wherever it is authorized; the root access map shows where that leads")
				fnd.Fix = "chmod 600 " + k.Path + " and keep ~/.ssh at 700; if other accounts may have copied it, replace the key and remove the old one from authorized_keys"
			}
			fnd.Detail = strings.Join(notes, "; ")
			out = append(out, fnd)
		}
		return out, ""
	},
}

func uid0(f *collect.Facts, user string) bool {
	for _, p := range f.Passwd {
		if p.Name == user {
			return p.UID == 0
		}
	}
	return false
}
