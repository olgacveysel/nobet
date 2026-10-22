package collect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPrivateKeysScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("needs ssh-keygen")
	}
	dir := t.TempDir()
	// Let other accounts through the test's own directories, as /home is.
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)

	var bodies []string // key material that must not leave the host
	newKey := func(path, comment string, mode os.FileMode, pub bool) string {
		t.Helper()
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		block, err := ssh.MarshalPrivateKey(sk, comment)
		if err != nil {
			t.Fatal(err)
		}
		body := pem.EncodeToMemory(block)
		bodies = append(bodies, strings.Split(string(body), "\n")[2])
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, mode)
		spk, _ := ssh.NewPublicKey(pk)
		if pub {
			os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(spk), 0o644)
		}
		return ssh.FingerprintSHA256(spk)
	}
	mkdir := func(p string, mode os.FileMode) {
		os.MkdirAll(p, mode)
		os.Chmod(p, mode)
	}
	home := func(name string) string { return filepath.Join(dir, "home", name) }
	for _, d := range []string{dir + "/home", dir + "/etc", dir + "/etc/ssh", dir + "/etc/ssl", dir + "/etc/ssl/private",
		dir + "/etc/backup", dir + "/opt", dir + "/opt/app", dir + "/opt/app/.ssh"} {
		mkdir(d, 0o755)
	}
	mkdir(home("alice"), 0o755)
	mkdir(home("alice")+"/.ssh", 0o755)
	mkdir(home("carol"), 0o700) // a closed home protects whatever is in it
	mkdir(home("carol")+"/.ssh", 0o755)
	mkdir(home("dave"), 0o750)
	mkdir(home("dave")+"/.ssh", 0o750)

	aliceFP := newKey(home("alice")+"/.ssh/id_ed25519", "alice@laptop", 0o644, true) // readable by everyone
	newKey(home("alice")+"/.ssh/id_safe", "", 0o600, false)
	os.Symlink(home("alice")+"/.ssh/id_ed25519", home("alice")+"/.ssh/id_link")
	os.WriteFile(home("alice")+"/.ssh/notes", []byte("not a key\n"), 0o644)
	newKey(home("carol")+"/.ssh/id_ed25519", "", 0o644, false)
	daveFP := newKey(home("dave")+"/.ssh/id_ed25519", "", 0o640, false) // readable by the staff group; no .pub
	hostFP := newKey(dir+"/etc/ssh/ssh_host_ed25519_key", "", 0o644, false)
	os.WriteFile(dir+"/etc/ssl/private/site.key", []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkq\n-----END ENCRYPTED PRIVATE KEY-----\n"), 0o644)
	os.Chmod(dir+"/etc/ssl/private/site.key", 0o644)
	bodies = append(bodies, "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkq")

	// Keys outside ~/.ssh that ssh configurations name, and an application's
	// deploy key under /opt. A key a config names twice, or that the
	// ~/.ssh listing finds too, counts once.
	backupFP := newKey(dir+"/etc/backup/id_backup", "backup", 0o644, false)
	os.WriteFile(dir+"/etc/ssh/ssh_config", []byte("Host backup.example.com\n    IdentityFile "+dir+"/etc/backup/id_backup\nHost *\n    IdentityFile ~/.ssh/id_rsa\n"), 0o644)
	mkdir(home("alice")+"/keys", 0o755)
	deployFP := newKey(home("alice")+"/keys/deploy", "", 0o644, true)
	secondFP := newKey(home("alice")+"/keys/second", "", 0o644, false)
	os.WriteFile(home("alice")+"/.ssh/config", []byte("Host git\n  IdentityFile ~/keys/deploy\n  identityfile=\"%d/keys/second\"\nHost other\n  IdentityFile ~/.ssh/id_ed25519\n  IdentityFile %d/keys/deploy\n"), 0o644)
	appFP := newKey(dir+"/opt/app/.ssh/deploy_key", "", 0o644, false)

	// Every file belongs to the test's own uid and gid. The accounts have
	// other primary groups, so staff (the files' group) has only eve in it.
	uid, gid := os.Getuid(), os.Getgid()
	passwd := ""
	for _, n := range []string{"alice", "carol", "dave"} {
		passwd += n + ":x:" + strconv.Itoa(uid) + ":50000::" + home(n) + ":/bin/sh\n"
	}
	os.WriteFile(dir+"/etc/passwd", []byte(passwd), 0o644)

	script := strings.NewReplacer("/etc/", dir+"/etc/", "/opt/", dir+"/opt/", "/srv/", dir+"/srv/").Replace(privateKeysScript)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		if strings.Contains(string(out), b) {
			t.Fatalf("key material left the host:\n%s", out)
		}
	}
	f := &Facts{
		Passwd: []PasswdEntry{{Name: "alice", UID: uid, GID: 50000, Home: home("alice")}, {Name: "carol", UID: uid, GID: 50000, Home: home("carol")},
			{Name: "dave", UID: uid, GID: 50000, Home: home("dave")}, {Name: "eve", UID: uid + 1, GID: 50001, Home: home("eve")}},
		Groups: []GroupEntry{{Name: "staff", GID: gid, Members: []string{"eve"}}},
	}
	got := f.parsePrivateKeys(string(out))
	want := []PrivateKey{ // by path
		{Path: dir + "/etc/backup/id_backup", Kind: "ssh", Format: "OPENSSH", Fingerprint: backupFP, Owner: "alice", Everyone: true},
		{Path: dir + "/etc/ssh/ssh_host_ed25519_key", Kind: "host", Format: "OPENSSH", Fingerprint: hostFP, Owner: "alice", Everyone: true},
		{Path: dir + "/etc/ssl/private/site.key", Kind: "tls", Format: "ENCRYPTED", Owner: "alice", Everyone: true},
		{Path: home("alice") + "/.ssh/id_ed25519", Kind: "ssh", Format: "OPENSSH", Fingerprint: aliceFP, Owner: "alice", Everyone: true},
		{Path: home("alice") + "/keys/deploy", Kind: "ssh", Format: "OPENSSH", Fingerprint: deployFP, Owner: "alice", Everyone: true},
		{Path: home("alice") + "/keys/second", Kind: "ssh", Format: "OPENSSH", Fingerprint: secondFP, Owner: "alice", Everyone: true},
		{Path: home("dave") + "/.ssh/id_ed25519", Kind: "ssh", Format: "OPENSSH", Fingerprint: daveFP, Owner: "alice", Group: "staff", Readers: []string{"eve"}},
		{Path: dir + "/opt/app/.ssh/deploy_key", Kind: "ssh", Format: "OPENSSH", Fingerprint: appFP, Owner: "alice", Everyone: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v\noutput:\n%s", got, want, out)
	}
	if f.parsePrivateKeys(strings.TrimSuffix(string(out), "@@end\n")) != nil {
		t.Error("output without @@end parsed")
	}
}

// A key in a closed home that an ACL lets one other account read, with
// the real getfacl.
func TestPrivateKeysACL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	for _, tool := range []string{"ssh-keygen", "setfacl", "getfacl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	alice := filepath.Join(dir, "home", "alice")
	os.MkdirAll(alice+"/.ssh", 0o700)
	os.Chmod(filepath.Join(dir, "home"), 0o755)
	os.Chmod(alice, 0o700)
	key := alice + "/.ssh/id_ed25519"
	if err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).Run(); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	bob := strconv.Itoa(uid + 1)
	if out, err := exec.Command("setfacl", "-m", "u:"+bob+":x", alice, alice+"/.ssh").CombinedOutput(); err != nil {
		t.Skipf("no ACLs here: %s", out)
	}
	if out, err := exec.Command("setfacl", "-m", "u:"+bob+":r", key).CombinedOutput(); err != nil {
		t.Fatalf("setfacl: %s", out)
	}
	os.MkdirAll(dir+"/etc", 0o755)
	os.WriteFile(dir+"/etc/passwd", []byte("alice:x:"+strconv.Itoa(uid)+":50000::"+alice+":/bin/sh\n"), 0o644)
	script := strings.NewReplacer("/etc/", dir+"/etc/", "/opt/", dir+"/opt/", "/srv/", dir+"/srv/").Replace(privateKeysScript)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	f := &Facts{Passwd: []PasswdEntry{{Name: "alice", UID: uid, GID: 50000, Home: alice},
		{Name: "bob", UID: uid + 1, GID: 50001, Home: dir + "/home/bob"}, {Name: "carol", UID: uid + 2, GID: 50001, Home: dir + "/home/carol"}}}
	got := f.parsePrivateKeys(string(out))
	if len(got) != 1 || got[0].Path != key || got[0].Everyone || !got[0].ACL || !reflect.DeepEqual(got[0].Readers, []string{"bob"}) {
		t.Errorf("got %+v\noutput:\n%s", got, out)
	}
}
