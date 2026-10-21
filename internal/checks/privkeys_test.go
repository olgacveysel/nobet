package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestReadablePrivateKeys(t *testing.T) {
	f := &collect.Facts{
		IsRoot: true,
		Errors: map[string]string{},
		SSHD:   map[string][]string{"permitrootlogin": {"prohibit-password"}},
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "alice", UID: 1000}, {Name: "deploy", UID: 1001}},
		SudoRights: map[string][]collect.SudoEntry{
			"deploy": {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}},
		},
		// alice's laptop key and the CI key are authorized for root-capable
		// accounts on this host; the backup key only for alice.
		AuthKeys: []collect.AuthKey{
			{User: "root", Fingerprint: "SHA256:laptop"},
			{User: "deploy", Fingerprint: "SHA256:ci"},
			{User: "alice", Fingerprint: "SHA256:backup"},
		},
		PrivateKeys: []collect.PrivateKey{
			{Path: "/home/alice/.ssh/id_ed25519", Kind: "ssh", Format: "OPENSSH", Fingerprint: "SHA256:laptop", Owner: "alice", Everyone: true},
			{Path: "/home/alice/.ssh/backup", Kind: "ssh", Format: "OPENSSH", Fingerprint: "SHA256:backup", Owner: "alice", Everyone: true},
			{Path: "/srv/ci/.ssh/id_rsa", Kind: "ssh", Format: "RSA", Fingerprint: "SHA256:ci", Owner: "ci", Group: "ci", Readers: []string{"bob", "carol"}},
			{Path: "/home/dave/.ssh/id_ed25519", Kind: "ssh", Format: "OPENSSH", Owner: "dave", Group: "staff", Readers: []string{"eve"}},
			{Path: "/etc/ssh/ssh_host_ed25519_key", Kind: "host", Format: "OPENSSH", Fingerprint: "SHA256:host", Owner: "root", Everyone: true},
			{Path: "/etc/ssl/private/site.key", Kind: "tls", Format: "", Owner: "root", Everyone: true},
		},
	}
	got, skip := readablePrivateKeys.Run(f)
	if skip != "" || len(got) != 6 {
		t.Fatalf("got %d (skip %q): %+v", len(got), skip, got)
	}
	want := []struct {
		sev           Severity
		title, detail string
	}{
		{Critical, "SSH private key /home/alice/.ssh/id_ed25519 can be read by every account", "SHA256:laptop; it logs in as root on this host"},
		{High, "SSH private key /home/alice/.ssh/backup can be read by every account", "SHA256:backup; whoever has it"},
		{High, "SSH private key /srv/ci/.ssh/id_rsa can be read by the ci group (bob, carol)", "it logs in as deploy, who can become root on this host"},
		{Medium, "SSH private key /home/dave/.ssh/id_ed25519 can be read by the staff group (eve)", "whoever has it"},
		{High, "sshd's host key /etc/ssh/ssh_host_ed25519_key can be read by every account", "pose as this server"},
		{High, "TLS private key /etc/ssl/private/site.key can be read by every account", "pose as the sites"},
	}
	for i, w := range want {
		g := got[i]
		if g.CheckID != "FS-004" || g.Severity != w.sev || g.Title != w.title || !strings.Contains(g.Detail, w.detail) || !strings.Contains(g.Fix, "chmod 600") {
			t.Errorf("finding %d:\n got  %v %q %q\n want %v %q %q", i, g.Severity, g.Title, g.Detail, w.sev, w.title, w.detail)
		}
	}

	f.PrivateKeys = []collect.PrivateKey{}
	if got, skip := readablePrivateKeys.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("no readable keys: %+v %q", got, skip)
	}
	if _, skip := readablePrivateKeys.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
}
