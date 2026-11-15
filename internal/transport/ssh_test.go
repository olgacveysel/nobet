package transport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testServer is an in-process SSH server: it accepts one client key, runs
// "commands" (echo, exit N, sleep) and, as a jump host, forwards
// direct-tcpip channels.
type testServer struct {
	addr     string
	forwards atomic.Int32 // direct-tcpip channels opened through it
	commands atomic.Int32
}

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	switch kind {
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	default:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startServer(t *testing.T, hostKeys []ssh.Signer, client ssh.PublicKey, forward bool) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(client.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &testServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg, forward)
		}
	}()
	return s
}

func (s *testServer) serve(c net.Conn, cfg *ssh.ServerConfig, forward bool) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go s.session(ch, creqs)
		case "direct-tcpip":
			if !forward {
				nc.Reject(ssh.Prohibited, "no forwarding")
				continue
			}
			var to struct {
				Host  string
				Port  uint32
				OHost string
				OPort uint32
			}
			ssh.Unmarshal(nc.ExtraData(), &to)
			if to.Port == 9 { // a target behind a firewall that drops packets: no answer
				go func() { time.Sleep(10 * time.Second); nc.Reject(ssh.ConnectionFailed, "timeout") }()
				continue
			}
			dst, err := net.Dial("tcp", net.JoinHostPort(to.Host, itoa(to.Port)))
			if err != nil {
				nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				dst.Close()
				continue
			}
			s.forwards.Add(1)
			go ssh.DiscardRequests(creqs)
			go func() { io.Copy(ch, dst); ch.CloseWrite() }()
			go func() { io.Copy(dst, ch); dst.Close() }()
		default:
			nc.Reject(ssh.UnknownChannelType, "no")
		}
	}
}

func (s *testServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		r.Reply(true, nil)
		s.commands.Add(1)
		var p struct{ Cmd string }
		ssh.Unmarshal(r.Payload, &p)
		status := uint32(0)
		switch {
		case p.Cmd == "flood": // output without end, until the client hangs up
			chunk := []byte(strings.Repeat("x", 32<<10))
			for i := 0; i < 4096; i++ {
				if _, err := ch.Write(chunk); err != nil {
					return
				}
			}
		case p.Cmd == "sleep":
			time.Sleep(5 * time.Second)
		case strings.HasPrefix(p.Cmd, "exit "):
			n := 0
			for _, d := range p.Cmd[5:] {
				n = n*10 + int(d-'0')
			}
			status = uint32(n)
			io.WriteString(ch.Stderr(), "failing\n")
		default:
			io.WriteString(ch, "ran: "+p.Cmd+"\n")
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, status)
		ch.SendRequest("exit-status", false, b)
		return
	}
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// clientKey writes an unencrypted client key file and returns its path.
func clientKey(t *testing.T, s ssh.Signer, raw any) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func knownHosts(t *testing.T, entries map[string][]ssh.PublicKey) string {
	t.Helper()
	var b strings.Builder
	for addr, keys := range entries {
		for _, k := range keys {
			b.WriteString(knownhosts.Line([]string{knownhosts.Normalize(addr)}, k) + "\n")
		}
	}
	p := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(p, []byte(b.String()), 0o600)
	return p
}

type rig struct {
	key     string        // client key file
	pub     ssh.PublicKey // its public half
	hostKey ssh.Signer
}

func newRig(t *testing.T) rig {
	t.Helper()
	// No ssh-agent from the environment: only the key file may log in.
	t.Setenv("SSH_AUTH_SOCK", "")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return rig{key: clientKey(t, signer, priv), pub: signer.PublicKey(), hostKey: newSigner(t, "ed25519")}
}

func (r rig) opts(known string) SSHOptions {
	return SSHOptions{KnownHostsFile: known, KeyFiles: []string{r.key}, Timeout: 3 * time.Second, CommandTimeout: 2 * time.Second}
}

func TestSSHRunAndExitCodes(t *testing.T) {
	r := newRig(t)
	srv := startServer(t, []ssh.Signer{r.hostKey}, r.pub, false)
	c, err := DialSSH(SSHTarget{Addr: srv.addr, User: "scan"}, r.opts(knownHosts(t, map[string][]ssh.PublicKey{srv.addr: {r.hostKey.PublicKey()}})))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Run("id -u")
	if err != nil || res.Stdout != "ran: id -u\n" || res.ExitCode != 0 {
		t.Errorf("run: %+v, %v", res, err)
	}
	// A non-zero exit is a result, not an error.
	res, err = c.Run("exit 3")
	if err != nil || res.ExitCode != 3 || res.Stderr != "failing\n" {
		t.Errorf("exit 3: %+v, %v", res, err)
	}
	// A command that runs too long is an error.
	start := time.Now()
	if _, err = c.Run("sleep"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("sleep: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Error("the command timeout did not stop waiting")
	}
}

func TestSSHHostKeys(t *testing.T) {
	r := newRig(t)
	srv := startServer(t, []ssh.Signer{r.hostKey}, r.pub, false)
	target := SSHTarget{Addr: srv.addr, User: "scan"}

	// Unknown host: refused, never trusted on first use.
	_, err := DialSSH(target, r.opts(knownHosts(t, nil)))
	if err == nil || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Errorf("unknown host: %v", err)
	}
	// Changed key: refused loudly.
	other := newSigner(t, "ed25519")
	_, err = DialSSH(target, r.opts(knownHosts(t, map[string][]ssh.PublicKey{srv.addr: {other.PublicKey()}})))
	if err == nil || !strings.Contains(err.Error(), "HOST KEY MISMATCH") {
		t.Errorf("changed key: %v", err)
	}
	// A wrong client key: authentication fails.
	stranger := newRig(t)
	_, err = DialSSH(target, stranger.opts(knownHosts(t, map[string][]ssh.PublicKey{srv.addr: {r.hostKey.PublicKey()}})))
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("wrong client key: %v", err)
	}
}

// The server offers an ECDSA and an ed25519 host key; known_hosts holds
// only the ed25519 one. x/crypto prefers ECDSA, so without asking for the
// stored type the ECDSA key would look like a changed one.
func TestSSHStoredKeyType(t *testing.T) {
	r := newRig(t)
	ec := newSigner(t, "ecdsa")
	srv := startServer(t, []ssh.Signer{r.hostKey, ec}, r.pub, false)
	c, err := DialSSH(SSHTarget{Addr: srv.addr, User: "scan"}, r.opts(knownHosts(t, map[string][]ssh.PublicKey{srv.addr: {r.hostKey.PublicKey()}})))
	if err != nil {
		t.Fatalf("ed25519 in known_hosts, ECDSA offered too: %v", err)
	}
	c.Close()
}

func TestSSHJumpChain(t *testing.T) {
	r := newRig(t)
	jumpKey, targetKey := newSigner(t, "ed25519"), newSigner(t, "ed25519")
	jump := startServer(t, []ssh.Signer{jumpKey}, r.pub, true)
	target := startServer(t, []ssh.Signer{targetKey}, r.pub, false)
	both := knownHosts(t, map[string][]ssh.PublicKey{jump.addr: {jumpKey.PublicKey()}, target.addr: {targetKey.PublicKey()}})

	c, err := DialSSH(SSHTarget{Addr: target.addr, User: "scan", Jump: &SSHTarget{Addr: jump.addr, User: "hop"}}, r.opts(both))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run("uname")
	c.Close()
	if err != nil || res.Stdout != "ran: uname\n" {
		t.Errorf("through the jump host: %+v, %v", res, err)
	}
	if jump.forwards.Load() != 1 || jump.commands.Load() != 0 || target.commands.Load() != 1 {
		t.Errorf("forwards %d, jump commands %d, target commands %d", jump.forwards.Load(), jump.commands.Load(), target.commands.Load())
	}

	// The jump host's key is checked as strictly as the target's.
	onlyTarget := knownHosts(t, map[string][]ssh.PublicKey{target.addr: {targetKey.PublicKey()}})
	_, err = DialSSH(SSHTarget{Addr: target.addr, User: "scan", Jump: &SSHTarget{Addr: jump.addr, User: "hop"}}, r.opts(onlyTarget))
	if err == nil || !strings.Contains(err.Error(), "jump host "+jump.addr) || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Errorf("unknown jump host: %v", err)
	}

	// A loop of jumps ends.
	loop := &SSHTarget{Addr: jump.addr, User: "hop"}
	loop.Jump = loop
	if _, err = DialSSH(SSHTarget{Addr: target.addr, Jump: loop}, r.opts(both)); err == nil || !strings.Contains(err.Error(), "too many jump hosts") {
		t.Errorf("jump loop: %v", err)
	}
}

// A server that accepts the connection and never answers: the handshake
// timeout ends the wait.
func TestSSHHandshakeTimeout(t *testing.T) {
	r := newRig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // hold it open, say nothing
		}
	}()
	o := r.opts(knownHosts(t, nil))
	o.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err = DialSSH(SSHTarget{Addr: ln.Addr().String(), User: "scan"}, o)
	if err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("silent server: %v after %s", err, time.Since(start))
	}
}

// A host that prints without end is stopped at the cap, and the
// connection stays usable.
func TestSSHOutputCap(t *testing.T) {
	old := maxOutput
	maxOutput = 1 << 20
	defer func() { maxOutput = old }()
	r := newRig(t)
	srv := startServer(t, []ssh.Signer{r.hostKey}, r.pub, false)
	c, err := DialSSH(SSHTarget{Addr: srv.addr, User: "scan"}, r.opts(knownHosts(t, map[string][]ssh.PublicKey{srv.addr: {r.hostKey.PublicKey()}})))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Run("flood"); err == nil || !strings.Contains(err.Error(), "more than 1 MB") {
		t.Errorf("flood: %v", err)
	}
	if res, err := c.Run("id"); err != nil || res.Stdout != "ran: id\n" {
		t.Errorf("after the flood: %+v, %v", res, err)
	}
}

// A jump host that never gets an answer from the target (a firewall that
// drops packets) does not hold the scan beyond the timeout.
func TestSSHJumpDialTimeout(t *testing.T) {
	r := newRig(t)
	jumpKey := newSigner(t, "ed25519")
	jump := startServer(t, []ssh.Signer{jumpKey}, r.pub, true)
	o := r.opts(knownHosts(t, map[string][]ssh.PublicKey{jump.addr: {jumpKey.PublicKey()}}))
	o.Timeout = 500 * time.Millisecond
	start := time.Now()
	_, err := DialSSH(SSHTarget{Addr: "10.0.0.1:9", User: "scan", Jump: &SSHTarget{Addr: jump.addr, User: "hop"}}, o)
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 3*time.Second {
		t.Errorf("silent target behind the jump host: %v after %s", err, time.Since(start))
	}
}
