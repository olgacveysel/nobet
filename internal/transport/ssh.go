package transport

// Host keys are always verified against known_hosts: a security auditor
// must never silently trust an unknown or changed host key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/olgacveysel/nobet/internal/runner"
)

// SSHOptions controls how SSH connections are made.
type SSHOptions struct {
	KnownHostsFile string
	KeyFiles       []string      // tried in addition to ssh-agent; encrypted keys are skipped
	Timeout        time.Duration // TCP connect + SSH handshake
	CommandTimeout time.Duration // per remote command; 0 means no limit
}

// DefaultSSHOptions uses the standard OpenSSH locations under ~/.ssh.
func DefaultSSHOptions() SSHOptions {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ssh")
	return SSHOptions{
		KnownHostsFile: filepath.Join(dir, "known_hosts"),
		KeyFiles: []string{
			filepath.Join(dir, "id_ed25519"),
			filepath.Join(dir, "id_ecdsa"),
			filepath.Join(dir, "id_rsa"),
		},
		Timeout:        10 * time.Second,
		CommandTimeout: 30 * time.Second,
	}
}

// SSHTarget is a fully resolved SSH destination.
type SSHTarget struct {
	Addr     string     // host:port to connect to
	User     string     // login user
	KeyFiles []string   // identity files for this host (from ssh_config), tried before the defaults
	Jump     *SSHTarget // bastion to connect through (may itself have a Jump), or nil
}

// SSH is an open connection to a remote host.
type SSH struct {
	conn       *ssh.Client
	jumps      []*ssh.Client // bastion connections, closed with conn
	agentConn  net.Conn
	cmdTimeout time.Duration
}

// DialSSH connects to t, through its jump hosts if it has any.
func DialSSH(t SSHTarget, opts SSHOptions) (*SSH, error) {
	hostKeys, err := knownhosts.New(opts.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts: %w", err)
	}

	// An unreachable agent is not an error: key files may still work.
	var agentSigners func() ([]ssh.Signer, error)
	agentConn, err := dialAgent()
	if err == nil && agentConn != nil {
		agentSigners = agent.NewClient(agentConn).Signers
	} else {
		agentConn = nil
	}

	s := &SSH{agentConn: agentConn, cmdTimeout: opts.CommandTimeout}
	client, err := s.dial(t, hostKeys, agentSigners, opts, 0)
	if err != nil {
		s.closeAll()
		return nil, err
	}
	s.conn = client
	return s, nil
}

const maxJumps = 8

// dial connects to t, first dialing its jump chain. Every jump client is
// recorded in s.jumps so Close can tear the chain down.
func (s *SSH) dial(t SSHTarget, hostKeys ssh.HostKeyCallback, agentSigners func() ([]ssh.Signer, error), opts SSHOptions, depth int) (*ssh.Client, error) {
	if depth > maxJumps {
		return nil, errors.New("too many jump hosts (ProxyJump loop?)")
	}

	var auth []ssh.AuthMethod
	if signers := loadSigners(t.KeyFiles); len(signers) > 0 {
		auth = append(auth, ssh.PublicKeys(signers...))
	}
	if agentSigners != nil {
		auth = append(auth, ssh.PublicKeysCallback(agentSigners))
	}
	if signers := loadSigners(opts.KeyFiles); len(signers) > 0 {
		auth = append(auth, ssh.PublicKeys(signers...))
	}
	if len(auth) == 0 {
		return nil, errors.New("no SSH credentials: start ssh-agent (or the OpenSSH Authentication Agent service on Windows) or pass an unencrypted key with -identity")
	}
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              auth,
		HostKeyCallback:   hostKeys,
		HostKeyAlgorithms: knownAlgorithms(hostKeys, t.Addr),
		Timeout:           opts.Timeout,
	}

	var conn net.Conn
	var err error
	if t.Jump != nil {
		jump, err := s.dial(*t.Jump, hostKeys, agentSigners, opts, depth+1)
		if err != nil {
			return nil, fmt.Errorf("jump host %s: %w", t.Jump.Addr, err)
		}
		s.jumps = append(s.jumps, jump)
		conn, err = jump.Dial("tcp", t.Addr)
		if err != nil {
			return nil, fmt.Errorf("connecting to %s through %s: %w", t.Addr, t.Jump.Addr, err)
		}
	} else {
		conn, err = net.DialTimeout("tcp", t.Addr, opts.Timeout)
		if err != nil {
			return nil, err
		}
	}

	client, err := handshake(conn, t.Addr, cfg, opts.Timeout)
	if err != nil {
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				return nil, fmt.Errorf("host key for %s is not in known_hosts; connect once with ssh to verify it", t.Addr)
			}
			return nil, fmt.Errorf("HOST KEY MISMATCH for %s: the key differs from known_hosts (reinstalled host or man-in-the-middle?)", t.Addr)
		}
		return nil, err
	}
	return client, nil
}

// handshake runs the SSH handshake over conn, giving up after timeout.
// Connections tunneled through a jump host do not support deadlines, so
// the timeout closes the connection instead.
func handshake(conn net.Conn, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	type result struct {
		c     ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		done <- result{c, chans, reqs, err}
	}()

	var timer <-chan time.Time
	if timeout > 0 {
		timer = time.After(timeout)
	}
	select {
	case r := <-done:
		if r.err != nil {
			conn.Close()
			return nil, r.err
		}
		return ssh.NewClient(r.c, r.chans, r.reqs), nil
	case <-timer:
		conn.Close()
		return nil, fmt.Errorf("SSH handshake with %s timed out after %s", addr, timeout)
	}
}

// Run executes cmd through the remote user's shell.
func (c *SSH) Run(cmd string) (runner.Result, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return runner.Result{}, err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	var runErr error
	if c.cmdTimeout > 0 {
		select {
		case runErr = <-done:
		case <-time.After(c.cmdTimeout):
			sess.Close()
			return runner.Result{}, fmt.Errorf("command timed out after %s", c.cmdTimeout)
		}
	} else {
		runErr = <-done
	}

	res := runner.Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, runErr
	}
	return res, nil
}

// Close closes the connection, its jump hosts and any agent socket.
func (c *SSH) Close() error {
	var err error
	if c.conn != nil {
		err = c.conn.Close()
	}
	c.closeAll()
	return err
}

func (c *SSH) closeAll() {
	for i := len(c.jumps) - 1; i >= 0; i-- {
		c.jumps[i].Close()
	}
	c.jumps = nil
	if c.agentConn != nil {
		c.agentConn.Close()
		c.agentConn = nil
	}
}

func loadSigners(paths []string) []ssh.Signer {
	var out []ssh.Signer
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue // passphrase-protected keys are expected to come from ssh-agent
		}
		out = append(out, s)
	}
	return out
}

// knownAlgorithms returns the host key algorithms known_hosts already holds
// for addr. Without this, the server may offer a key type we have no entry
// for (say ECDSA when we only stored ED25519), which knownhosts reports as a
// mismatch. We find the stored types by probing the callback with a
// throwaway key: the resulting KeyError lists the keys it expected.
func knownAlgorithms(cb ssh.HostKeyCallback, addr string) []string {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil
	}
	var remoteAddr net.Addr = &net.TCPAddr{IP: net.IPv4zero}
	if a, err := net.ResolveTCPAddr("tcp", addr); err == nil {
		remoteAddr = a
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(cb(addr, remoteAddr, probe.PublicKey()), &keyErr) {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a ...string) {
		for _, x := range a {
			if !seen[x] {
				seen[x] = true
				algos = append(algos, x)
			}
		}
	}
	for _, k := range keyErr.Want {
		if t := k.Key.Type(); t == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		} else {
			add(t)
		}
	}
	return algos
}
