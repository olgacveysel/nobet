package rootmap

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func TestBuildExposedKeys(t *testing.T) {
	// The laptop key reaches root on db01; on web01, a copy of its private
	// half is readable by everyone and one by a group. A readable key that
	// reaches root nowhere is not part of the map.
	db := &collect.Facts{
		SSHD:         map[string][]string{"permitrootlogin": {"prohibit-password"}},
		Passwd:       []collect.PasswdEntry{{Name: "root", UID: 0}},
		AuthKeys:     []collect.AuthKey{{User: "root", Fingerprint: fpLaptop, Type: "ssh-ed25519"}},
		RootWritable: []collect.WritablePath{},
	}
	web := &collect.Facts{
		Passwd:       []collect.PasswdEntry{{Name: "root", UID: 0}},
		AuthKeys:     []collect.AuthKey{},
		RootWritable: []collect.WritablePath{},
		PrivateKeys: []collect.PrivateKey{
			{Path: "/home/alice/.ssh/id_ed25519", Kind: "ssh", Fingerprint: fpLaptop, Owner: "alice", Everyone: true},
			{Path: "/srv/ci/.ssh/id_ed25519", Kind: "ssh", Fingerprint: fpLaptop, Owner: "ci", Group: "ci", Readers: []string{"bob"}},
			{Path: "/home/bob/.ssh/old", Kind: "ssh", Fingerprint: "SHA256:nowhere", Owner: "bob", Everyone: true},
		},
	}
	m := Build([]scan.HostResult{{Host: "db01", Facts: db}, {Host: "web01", Facts: web}})
	if len(m.Keys) != 1 {
		t.Fatalf("keys: %+v", m.Keys)
	}
	want := []Exposure{
		{Host: "web01", Path: "/home/alice/.ssh/id_ed25519", Who: "every account"},
		{Host: "web01", Path: "/srv/ci/.ssh/id_ed25519", Who: "the ci group (bob)"},
	}
	if !reflect.DeepEqual(m.Keys[0].Exposed, want) {
		t.Errorf("exposed: %+v", m.Keys[0].Exposed)
	}
	var buf bytes.Buffer
	m.WriteText(&buf)
	if !strings.Contains(buf.String(), "  ! private key readable by every account on web01: /home/alice/.ssh/id_ed25519\n") {
		t.Errorf("text:\n%s", buf.String())
	}
}
