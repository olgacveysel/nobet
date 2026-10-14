package collect

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// Socket states in /proc/net/tcp and udp.
const (
	tcpListen = "0A"
	udpUnconn = "07" // what ss -l lists for UDP
)

// bigEndianArch lists `uname -m` values of big-endian machines, whose
// /proc/net addresses are not byte-swapped.
var bigEndianArch = set("s390", "s390x", "ppc", "ppc64", "mips", "mips64", "sparc", "sparc64",
	"m68k", "armeb", "aarch64_be", "parisc", "parisc64")

// parseListeners reads listenersScript output: ss output, or the kernel
// tables after an "@@proc <arch>" line.
func parseListeners(s string) []Listener {
	if rest, ok := strings.CutPrefix(strings.TrimLeft(s, "\n"), "@@proc "); ok {
		arch, body, _ := strings.Cut(rest, "\n")
		return parseProcNet(body, bigEndianArch[strings.TrimSpace(arch)])
	}
	return parseSS(s)
}

// parseProcNet parses "proto local_address state" lines taken from
// /proc/net/{tcp,tcp6,udp,udp6}, for example:
//
//	tcp 0B00007F:A0DD 0A
//	tcp6 00000000000000000000000000000000:0016 0A
func parseProcNet(s string, bigEndian bool) []Listener {
	var out []Listener
	for _, line := range lines(s) {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		proto := strings.TrimSuffix(f[0], "6")
		if !(proto == "tcp" && f[2] == tcpListen || proto == "udp" && f[2] == udpUnconn) {
			continue
		}
		hexAddr, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}
		addr, ok := procAddr(hexAddr, bigEndian)
		if !ok {
			continue
		}
		out = append(out, Listener{Proto: proto, Addr: addr, Port: int(port)})
	}
	return out
}

// procAddr decodes an address from /proc/net: 4 or 16 bytes in hex, made
// of 32-bit words in host byte order.
func procAddr(h string, bigEndian bool) (string, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", false
	}
	if !bigEndian {
		for i := 0; i < len(b); i += 4 {
			b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
		}
	}
	a, ok := netip.AddrFromSlice(b)
	return a.String(), ok
}
