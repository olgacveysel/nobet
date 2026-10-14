package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

// TestDialAgentPipe serves an in-memory agent on a named pipe and lists
// its keys through dialAgent, the way DialSSH uses it.
func TestDialAgentPipe(t *testing.T) {
	pipe := fmt.Sprintf(`\\.\pipe\nobet-test-agent-%d`, os.Getpid())
	l, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	keyring := agent.NewKeyring()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "pipe-test"}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(keyring, c) }()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", pipe)
	conn, err := dialAgent()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) != 1 {
		t.Fatalf("signers %d, err %v", len(signers), err)
	}

	t.Setenv("SSH_AUTH_SOCK", `\\.\pipe\nobet-no-such-agent`)
	if c, err := dialAgent(); err == nil {
		c.Close()
		t.Error("dialing a missing pipe should fail")
	}
}
