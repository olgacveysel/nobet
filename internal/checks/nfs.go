package checks

import (
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// everyHost reports whether an export's client spec matches every host.
// nfs-utils matches nobody with 0.0.0.0/0 (checked on 2.8.3), but does
// with 0.0.0.0/0.0.0.0.
func everyHost(client string) bool {
	return client == "*" || client == "0.0.0.0/0.0.0.0"
}

var nfsExports = Check{
	ID:    "NET-003",
	Title: "Risky NFS exports",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.NFSExports == nil {
			return nil, "could not read the NFS export table: " + f.Errors["nfs"]
		}
		// One finding per directory and kind of exposure, naming every
		// client it applies to.
		type kind struct {
			path                 string
			write, asRoot, world bool
		}
		groups := map[kind][]collect.NFSExport{}
		var order []kind
		for _, e := range f.NFSExports {
			world := everyHost(e.Client)
			switch {
			case e.AsRoot() && (e.Write || world):
			case world && e.AsAnyone():
			default:
				// Root squashed and named clients, or root reading
				// everything on named clients (a backup host): NFS as
				// designed.
				continue
			}
			k := kind{e.Path, e.Write, e.AsRoot(), world}
			if groups[k] == nil {
				order = append(order, k)
			}
			groups[k] = append(groups[k], e)
		}
		var out []Finding
		for _, k := range order {
			es := groups[k]
			var clients, options []string
			insecure, noSquash, anonRoot, allRoot := false, false, false, false
			for _, e := range es {
				clients = append(clients, e.Client)
				options = append(options, e.Client+"("+nfsOptions(e)+")")
				insecure = insecure || e.Insecure
				noSquash = noSquash || (!e.RootSquash && !e.AllSquash)
				anonRoot = anonRoot || e.AnonRoot
				allRoot = allRoot || (e.AllSquash && e.AnonRoot)
			}
			who, verb, as := "any machine", "read", "any account but root"
			if !k.world {
				who = summarize(clients, 4)
			}
			if k.write {
				verb = "write"
			}
			if k.asRoot {
				as = "root"
			}
			var sev Severity
			switch {
			case k.asRoot && k.write && k.world:
				sev = Critical
			case k.asRoot || k.write:
				sev = High
			default:
				sev = Medium
			}
			notes := []string{"exported to " + summarize(options, 4)}
			var how string
			switch {
			case allRoot:
				how = "every account on a client, not only root, is root in it (all_squash with anonuid=0)"
			case k.asRoot:
				how = "root on a client is root in it"
			default:
				how = "with sec=sys the server takes the client's word for which account is asking, so whoever is root on a machine can " + verb + " as any other account"
			}
			if k.asRoot && k.write {
				how += ", and can change root's files there or plant a set-user-ID root program"
			}
			notes = append(notes, how)
			if k.world {
				notes = append(notes, "every host may mount it: whoever controls any machine that reaches port 2049, their own laptop say, can do this")
			}
			if insecure {
				notes = append(notes, "insecure accepts requests from unprivileged ports, so any account on a client can send them, not only root")
			}
			var fixes []string
			if k.asRoot && noSquash {
				fixes = append(fixes, "drop no_root_squash (root_squash is the default)")
			}
			if k.asRoot && anonRoot {
				fixes = append(fixes, "drop anonuid=0 (squashed requests must not become root)")
			}
			if k.world {
				fixes = append(fixes, "name the hosts or network that need it instead of *")
			}
			if !k.asRoot {
				fixes = append(fixes, "or require Kerberos (sec=krb5p)")
			}
			if insecure {
				fixes = append(fixes, "drop insecure")
			}
			out = append(out, Finding{
				CheckID:  "NET-003",
				Severity: sev,
				Title:    "NFS export " + k.path + " lets " + who + " " + verb + " it as " + as,
				Detail:   strings.Join(notes, "; "),
				Fix:      "In /etc/exports (or /etc/exports.d): " + strings.Join(fixes, ", ") + "; then run exportfs -ra",
			})
		}
		return out, ""
	},
}

// nfsOptions lists the options that decide the exposure, as exports(5)
// writes them.
func nfsOptions(e collect.NFSExport) string {
	o := []string{"ro"}
	if e.Write {
		o[0] = "rw"
	}
	switch {
	case e.AllSquash:
		o = append(o, "all_squash")
	case !e.RootSquash:
		o = append(o, "no_root_squash")
	}
	if e.AnonRoot {
		o = append(o, "anonuid=0")
	}
	if e.Insecure {
		o = append(o, "insecure")
	}
	return strings.Join(o, ",")
}
