package collect

import (
	"reflect"
	"testing"
)

// Lines as listenersScript prints them from a container running sshd and
// Docker's DNS resolver (taken from real /proc/net files).
const procOut = `@@proc x86_64
tcp local_address st
tcp 00000000:0016 0A
tcp 0B00007F:A0DD 0A
tcp 0F02000A:0016 01
tcp6 local_address st
tcp6 00000000000000000000000000000000:0016 0A
tcp6 0000000000000000FFFF00000100007F:1F90 0A
tcp6 00000000000000000000000001000000:0019 0A
udp 0B00007F:A752 07
udp 0F02000A:D431 01
`

func TestParseListenersProc(t *testing.T) {
	want := []Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{Proto: "tcp", Addr: "127.0.0.11", Port: 41181},
		{Proto: "tcp", Addr: "::", Port: 22},
		{Proto: "tcp", Addr: "::ffff:127.0.0.1", Port: 8080},
		{Proto: "tcp", Addr: "::1", Port: 25},
		{Proto: "udp", Addr: "127.0.0.11", Port: 42834},
	}
	if got := parseListeners(procOut); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}

	// The same socket on a big-endian machine (s390x).
	if got := parseListeners("@@proc s390x\ntcp 7F00000B:A0DD 0A\n"); len(got) != 1 || got[0].Addr != "127.0.0.11" {
		t.Errorf("big endian: %+v", got)
	}

	// ss output still goes through parseSS.
	if got := parseListeners("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"); len(got) != 1 || got[0].Port != 22 {
		t.Errorf("ss: %+v", got)
	}
}
