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

// etabSample is /var/lib/nfs/etab from nfs-utils 2.8.3 (Debian 13), written
// by exportfs -ra for a lab /etc/exports.
const etabSample = "/srv/with\\040space\t192.168.1.5(rw,sync,wdelay,hide,nocrossmnt,secure,no_root_squash,all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=8,anonuid=65534,anongid=65534,sec=sys,rw,secure,no_root_squash,all_squash)\n" +
	"/srv/anon\t172.31.9.20(rw,sync,wdelay,hide,nocrossmnt,secure,root_squash,all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=4,anonuid=0,anongid=0,sec=sys,rw,secure,root_squash,all_squash)\n" +
	"/srv/wide\t0.0.0.0/0(rw,sync,wdelay,hide,nocrossmnt,insecure,no_root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=6,anonuid=65534,anongid=65534,sec=sys,rw,insecure,no_root_squash,no_all_squash)\n" +
	"/srv/flavors\t172.31.9.0/24(ro,sync,wdelay,hide,nocrossmnt,secure,no_root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=3,anonuid=65534,anongid=65534,sec=krb5p,rw,secure,no_root_squash,no_all_squash,sec=sys,ro,secure,no_root_squash,no_all_squash)\n" +
	"/srv/krb\t*(rw,sync,wdelay,hide,nocrossmnt,secure,no_root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=7,anonuid=65534,anongid=65534,sec=krb5p,rw,secure,no_root_squash,no_all_squash)\n" +
	"/srv/pub\t*(ro,sync,wdelay,hide,nocrossmnt,secure,root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=5,anonuid=65534,anongid=65534,sec=sys,ro,secure,root_squash,no_all_squash)\n" +
	"/srv/squashed\t*(rw,sync,wdelay,hide,nocrossmnt,secure,root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=2,anonuid=65534,anongid=65534,sec=sys,rw,secure,root_squash,no_all_squash)\n" +
	"/srv/open\t*(rw,sync,wdelay,hide,nocrossmnt,secure,no_root_squash,no_all_squash,no_subtree_check,secure_locks,acl,no_pnfs,fsid=1,anonuid=65534,anongid=65534,sec=sys,rw,secure,no_root_squash,no_all_squash)\n"

func TestNFSScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	etab := filepath.Join(dir, "etab")
	threads := filepath.Join(dir, "threads")
	run := func() string {
		t.Helper()
		script := strings.NewReplacer("/var/lib/nfs/etab", etab, "/proc/fs/nfsd/threads", threads).Replace(nfsScript)
		out, err := exec.Command("/bin/sh", "-c", script).Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// No NFS server installed: no table.
	if got, why := parseNFSExports(run()); got == nil || len(got) != 0 || why != "" {
		t.Errorf("without etab: %v %q", got, why)
	}

	write(etab, etabSample)
	write(threads, "8\n")
	got, why := parseNFSExports(run())
	want := []NFSExport{
		{Path: "/srv/with space", Client: "192.168.1.5", Write: true, AllSquash: true, SysAuth: true},
		{Path: "/srv/anon", Client: "172.31.9.20", Write: true, RootSquash: true, AllSquash: true, AnonRoot: true, SysAuth: true},
		{Path: "/srv/wide", Client: "0.0.0.0/0", Write: true, Insecure: true, SysAuth: true},
		{Path: "/srv/flavors", Client: "172.31.9.0/24", SysAuth: true}, // sys gets ro; krb5p rw
		{Path: "/srv/krb", Client: "*", Write: true},                   // Kerberos only: no SysAuth
		{Path: "/srv/pub", Client: "*", RootSquash: true, SysAuth: true},
		{Path: "/srv/squashed", Client: "*", Write: true, RootSquash: true, SysAuth: true},
		{Path: "/srv/open", Client: "*", Write: true, SysAuth: true},
	}
	if why != "" || !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v (%q)\nwant %+v", got, why, want)
	}
	asRoot := map[string]bool{}
	for _, e := range got {
		asRoot[e.Path] = e.AsRoot()
	}
	wantRoot := map[string]bool{"/srv/with space": false, "/srv/anon": true, "/srv/wide": true, "/srv/flavors": true,
		"/srv/krb": false, "/srv/pub": false, "/srv/squashed": false, "/srv/open": true}
	if !reflect.DeepEqual(asRoot, wantRoot) {
		t.Errorf("AsRoot: got %v, want %v", asRoot, wantRoot)
	}

	// /proc/fs/nfsd not mounted: whether the server runs is unknown, so the
	// table counts.
	os.Remove(threads)
	if got, _ := parseNFSExports(run()); len(got) != len(want) {
		t.Errorf("without a thread count: %d exports, want %d", len(got), len(want))
	}
	// A table left behind while the server is stopped serves nothing.
	write(threads, "0\n")
	if got, why := parseNFSExports(run()); got == nil || len(got) != 0 || why != "" {
		t.Errorf("stopped server: %v %q", got, why)
	}

	if parse, _ := parseNFSExports(strings.TrimSuffix(run(), "@@end\n")); parse != nil {
		t.Error("output without @@end parsed")
	}
	if os.Geteuid() != 0 {
		os.Chmod(etab, 0)
		if got, why := parseNFSExports(run()); got != nil || why == "" {
			t.Errorf("unreadable etab: %v %q", got, why)
		}
	}
}
