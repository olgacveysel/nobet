package collect

import (
	"reflect"
	"testing"
)

func TestParseSS(t *testing.T) {
	out := `tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      128             [::]:3306           [::]:*
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
`
	want := []Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{Proto: "tcp", Addr: "::", Port: 3306},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53},
	}
	if got := parseSS(out); !reflect.DeepEqual(got, want) {
		t.Errorf("parseSS:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseSudoers(t *testing.T) {
	out := `/etc/sudoers: # This file MUST be edited with visudo
/etc/sudoers: Defaults	env_reset
/etc/sudoers: 
/etc/sudoers: #includedir /etc/sudoers.d
/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: ALL
`
	want := []SudoLine{
		{File: "/etc/sudoers", Text: "Defaults\tenv_reset"},
		{File: "/etc/sudoers", Text: "#includedir /etc/sudoers.d"},
		{File: "/etc/sudoers.d/deploy", Text: "deploy ALL=(ALL) NOPASSWD: ALL"},
	}
	if got := parseSudoers(out); !reflect.DeepEqual(got, want) {
		t.Errorf("parseSudoers:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseSSHD(t *testing.T) {
	out := "port 22\nPermitRootLogin no\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\n"
	got := parseSSHD(out)
	if v := got["permitrootlogin"]; len(v) != 1 || v[0] != "no" {
		t.Errorf("permitrootlogin = %v", v)
	}
	if v := got["hostkey"]; len(v) != 2 {
		t.Errorf("hostkey = %v, want 2 values", v)
	}
}

func TestParseUpdatesApt(t *testing.T) {
	out := `manager=apt
now=1760000000
refreshed=1759000000
refreshed=1759900000
rc=0
upd=openssl
sec=- openssl
upd=libssl3
sec=- libssl3
upd=vim
`
	u := parseUpdates(out)
	if u.Manager != "apt" || u.Total != 3 || len(u.Security) != 2 || u.Err != "" {
		t.Fatalf("got %+v", u)
	}
	if u.ListsAgeDays != 1 { // (1760000000-1759900000)/86400
		t.Errorf("ListsAgeDays = %d, want 1", u.ListsAgeDays)
	}
}

func TestParseUpdatesDnf(t *testing.T) {
	out := "manager=dnf\nrc=0\nsec=Important/Sec. openssl-1:3.0.7-27.el9.x86_64\nsec=Moderate/Sec. less-590-4.el9.x86_64\n"
	u := parseUpdates(out)
	want := []SecurityUpdate{
		{Package: "openssl", Severity: "important"},
		{Package: "less", Severity: "moderate"},
	}
	if !reflect.DeepEqual(u.Security, want) || u.Total != -1 {
		t.Errorf("got %+v", u)
	}

	if u := parseUpdates("manager=dnf\nrc=1\n"); u.Err == "" {
		t.Error("non-zero rc should set Err")
	}
	if u := parseUpdates("manager=zypper\nrc=100\n"); u.Err != "" {
		t.Errorf("zypper rc 100 is informational, got Err %q", u.Err)
	}
}

func TestParseUpdatesDnf5(t *testing.T) {
	// Real `dnf -q -C advisory list --security` lines, after the awk filter.
	out := `manager=dnf5
rc=0
sec=Moderate vim-data-2:9.2.390-1.fc42.noarch
sec=Moderate vim-minimal-2:9.2.390-1.fc42.x86_64
sec=Important krb5-libs-1.21.3-7.fc42.x86_64
sec=Important krb5-libs-1.21.3-8.fc42.x86_64
`
	u := parseUpdates(out)
	want := []SecurityUpdate{
		{Package: "vim-data", Severity: "moderate"},
		{Package: "vim-minimal", Severity: "moderate"},
		{Package: "krb5-libs", Severity: "important"},
	}
	if !reflect.DeepEqual(u.Security, want) || u.Err != "" {
		t.Errorf("got %+v", u)
	}

	// dnf5 exits 0 without a cache; that must not look like "no updates".
	if u := parseUpdates("manager=dnf5\nrc=0\nnocache=1\n"); u.Err == "" {
		t.Error("missing cache should set Err")
	}
}

func TestRPMName(t *testing.T) {
	for in, want := range map[string]string{
		"vim-data-2:9.2.390-1.fc42.noarch": "vim-data",
		"openssl-1:3.0.7-27.el9.x86_64":    "openssl",
		"kernel-5.14.0-503.el9":            "kernel",
		"weird":                            "weird",
	} {
		if got := rpmName(in); got != want {
			t.Errorf("rpmName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseReboot(t *testing.T) {
	r := parseReboot("running=6.1.0-17-amd64\nlatest=6.1.0-18-amd64\nflag=/run/reboot-required\npkg=linux-image-6.1.0-18-amd64\npkg=linux-image-6.1.0-18-amd64\n")
	if r.Running != "6.1.0-17-amd64" || r.Latest != "6.1.0-18-amd64" || len(r.Flags) != 1 || len(r.Packages) != 1 {
		t.Errorf("got %+v", r)
	}
}

func TestParseAuthKeys(t *testing.T) {
	out := "deploy\t/home/deploy/.ssh/authorized_keys\tssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMSyX8373YVG5mEJfutryUbvHC0Qlem82smJ3qzpPPfW test@nobet\n" +
		"root\t/root/.ssh/authorized_keys\tcommand=\"/usr/bin/backup\",from=\"10.0.0.5\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMSyX8373YVG5mEJfutryUbvHC0Qlem82smJ3qzpPPfW test@nobet\n" +
		"root\t/root/.ssh/authorized_keys\tnot a key\n"
	got := parseAuthKeys(out)
	if len(got) != 2 {
		t.Fatalf("got %d keys, want 2: %+v", len(got), got)
	}
	const fp = "SHA256:tnsW9C5rLuMoAPWUsJ5Xg9RNHs9bO+sCTSjFnQb4TA0"
	if got[0].User != "deploy" || got[0].Fingerprint != fp || got[0].Comment != "test@nobet" || got[0].Type != "ssh-ed25519" {
		t.Errorf("key 0: %+v", got[0])
	}
	if got[1].User != "root" || len(got[1].Options) != 2 {
		t.Errorf("key 1: %+v", got[1])
	}
}

func TestParseSudoRights(t *testing.T) {
	out := `@@user deploy
Matching Defaults entries for deploy on web01:
    env_reset, mail_badpass

User deploy may run the following commands on web01:
    (ALL) NOPASSWD: ALL
@@user backup
User backup may run the following commands on web01:
    (root) NOPASSWD: /usr/bin/rsync, /usr/bin/tar
@@user alice
User alice may run the following commands on web01:
    (ALL : ALL) ALL
@@user bob
User bob is not allowed to run sudo on web01.
`
	m, auth := parseSudoRights(out)
	if len(auth) != 0 {
		t.Errorf("default Defaults should not be recorded: %v", auth)
	}
	if e := m["deploy"]; len(e) != 1 || !e[0].NoPasswd || !e[0].RootAll() {
		t.Errorf("deploy: %+v", e)
	}
	if e := m["backup"]; len(e) != 1 || e[0].RootAll() || len(e[0].Commands) != 2 {
		t.Errorf("backup: %+v", e)
	}
	if e := m["alice"]; len(e) != 1 || e[0].NoPasswd || !e[0].RootAll() {
		t.Errorf("alice: %+v", e)
	}
	if len(m["bob"]) != 0 {
		t.Errorf("bob: %+v", m["bob"])
	}
}

func TestGroupMembers(t *testing.T) {
	f := &Facts{
		Passwd: []PasswdEntry{{Name: "svc", UID: 998, GID: 999}},
		Groups: parseGroup("docker:x:999:alice,bob\nwheel:x:10:alice\n"),
	}
	if got := f.GroupMembers("docker"); !reflect.DeepEqual(got, []string{"alice", "bob", "svc"}) {
		t.Errorf("docker members = %v", got)
	}
	if got := f.GroupMembers("lxd"); got != nil {
		t.Errorf("missing group should return nil, got %v", got)
	}
}

func TestParseFirewall(t *testing.T) {
	out := `ufw=Status: inactive
@@nft
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		counter accept
	}
}
@@end
@@iptables
-P INPUT ACCEPT
@@end
`
	fw := parseFirewall(out)
	if !fw.NftChecked || fw.NftInputRules != 3 || !fw.NftInputDrop || fw.IptInputRules != 0 || fw.IptInputPolicy != "ACCEPT" {
		t.Errorf("got %+v", fw)
	}
	if !fw.Active() || !fw.Known() {
		t.Error("nft input chain with drop policy should count as active")
	}

	none := parseFirewall("ufw=Status: inactive\n@@iptables\n-P INPUT ACCEPT\n-P FORWARD DROP\n-A FORWARD -j DOCKER\n@@end\n")
	if none.Active() {
		t.Errorf("only FORWARD rules (e.g. Docker) should not count as an input firewall: %+v", none)
	}

	// DOCKER-USER as Docker leaves it (older versions add a RETURN), for
	// IPv4 and IPv6, and with ufw-docker's rules in it.
	empty := parseFirewall("ufw=Status: active\n@@iptables\n-P INPUT DROP\n-A INPUT -j ufw-before-input\n@@end\n@@docker-user\n-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n-N DOCKER-USER\n@@end\n")
	if empty.DockerUserRules != 0 || empty.IptInputRules != 1 {
		t.Errorf("Docker's own DOCKER-USER: %+v", empty)
	}
	filtered := parseFirewall("@@docker-user\n-N DOCKER-USER\n-A DOCKER-USER -j ufw-user-forward\n-A DOCKER-USER -i eth0 -p tcp -m tcp --dport 5432 -j DROP\n-A DOCKER-USER -j RETURN\n@@end\n")
	if filtered.DockerUserRules != 2 {
		t.Errorf("ufw-docker rules: %+v", filtered)
	}
}

func TestParseFiles(t *testing.T) {
	suid, ww := parseFiles("suid=pkg /usr/bin/sudo\nsuid=none /opt/tool/bin/helper\nww=d /opt/shared\nww=f /etc/cron.d/job\n")
	if len(suid) != 2 || suid[1] != (SUIDFile{Path: "/opt/tool/bin/helper", Owner: "none"}) {
		t.Errorf("suid: %+v", suid)
	}
	if len(ww) != 2 || !ww[0].Dir || ww[1].Dir {
		t.Errorf("ww: %+v", ww)
	}
}
