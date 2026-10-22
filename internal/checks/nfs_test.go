package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestNFSExports(t *testing.T) {
	sys := func(e collect.NFSExport) collect.NFSExport { e.SysAuth = true; return e }
	f := &collect.Facts{Errors: map[string]string{}, NFSExports: []collect.NFSExport{
		sys(collect.NFSExport{Path: "/srv/open", Client: "*", Write: true}),
		sys(collect.NFSExport{Path: "/srv/backup", Client: "10.0.0.5", Write: true}),
		sys(collect.NFSExport{Path: "/srv/backup", Client: "10.0.0.6", Write: true, Insecure: true}),
		sys(collect.NFSExport{Path: "/srv/anon", Client: "10.0.0.7", Write: true, RootSquash: true, AllSquash: true, AnonRoot: true}),
		sys(collect.NFSExport{Path: "/srv/home", Client: "*", Write: true, RootSquash: true}),
		sys(collect.NFSExport{Path: "/srv/pub", Client: "0.0.0.0/0.0.0.0", RootSquash: true}),
		sys(collect.NFSExport{Path: "/srv/etc", Client: "*"}), // read as root
		// NFS as designed: root squashed for named clients, a backup host
		// reading as root, Kerberos, everyone squashed to nobody.
		sys(collect.NFSExport{Path: "/srv/data", Client: "10.0.0.0/24", Write: true, RootSquash: true}),
		sys(collect.NFSExport{Path: "/srv/data", Client: "backup.lan"}),
		{Path: "/srv/krb", Client: "*", Write: true},
		sys(collect.NFSExport{Path: "/srv/drop", Client: "*", Write: true, RootSquash: true, AllSquash: true}),
	}}
	got, skip := nfsExports.Run(f)
	type res struct {
		sev   Severity
		title string
	}
	want := []res{
		{Critical, "NFS export /srv/open lets any machine write it as root"},
		{High, "NFS export /srv/backup lets 10.0.0.5, 10.0.0.6 write it as root"},
		{High, "NFS export /srv/anon lets 10.0.0.7 write it as root"},
		{High, "NFS export /srv/home lets any machine write it as any account but root"},
		{Medium, "NFS export /srv/pub lets any machine read it as any account but root"},
		{High, "NFS export /srv/etc lets any machine read it as root"},
	}
	if skip != "" || len(got) != len(want) {
		t.Fatalf("got %d findings (skip %q), want %d: %+v", len(got), skip, len(want), got)
	}
	for i, w := range want {
		if got[i].CheckID != "NET-003" || got[i].Severity != w.sev || got[i].Title != w.title {
			t.Errorf("finding %d: got %v %q, want %v %q", i, got[i].Severity, got[i].Title, w.sev, w.title)
		}
	}
	for i, s := range map[int][]string{
		0: {"*(rw,no_root_squash)", "drop no_root_squash", "instead of *"},
		1: {"10.0.0.6(rw,no_root_squash,insecure)", "any account on a client", "drop insecure"},
		2: {"every account on a client", "drop anonuid=0"},
		3: {"takes the client's word", "sec=krb5p"},
	} {
		for _, part := range s {
			if !strings.Contains(got[i].Detail+" "+got[i].Fix, part) {
				t.Errorf("finding %d lacks %q: %s / %s", i, part, got[i].Detail, got[i].Fix)
			}
		}
	}

	f.NFSExports = []collect.NFSExport{}
	if got, skip := nfsExports.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("none: %+v %q", got, skip)
	}
	f.NFSExports, f.Errors["nfs"] = nil, "cannot read /var/lib/nfs/etab"
	if _, skip := nfsExports.Run(f); !strings.Contains(skip, "cannot read") {
		t.Errorf("unreadable: %q", skip)
	}
}
