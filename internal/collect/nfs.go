package collect

import (
	"strconv"
	"strings"
)

// NFSExport is one directory the NFS server exports to one client, with
// the options that decide whose word it takes for who is asking.
type NFSExport struct {
	Path       string `json:"path"`
	Client     string `json:"client"` // a host, network, @netgroup, wildcard name, or * for every host
	Write      bool   `json:"write,omitempty"`
	RootSquash bool   `json:"root_squash,omitempty"` // root on the client becomes the anonymous account
	AllSquash  bool   `json:"all_squash,omitempty"`  // every account on the client does
	AnonRoot   bool   `json:"anon_root,omitempty"`   // anonuid=0: the anonymous account is root
	Insecure   bool   `json:"insecure,omitempty"`    // requests from unprivileged ports too
	SysAuth    bool   `json:"sys_auth,omitempty"`    // sec=sys allowed: the client says which account is asking
}

// AsRoot reports whether root on the client acts as root in the export.
// Kerberos-only exports do not count: the client cannot just say so.
func (e NFSExport) AsRoot() bool {
	return e.SysAuth && ((!e.RootSquash && !e.AllSquash) || e.AnonRoot)
}

// AsAnyone reports whether the client can act as any account (but root,
// when squashed) by saying so.
func (e NFSExport) AsAnyone() bool { return e.SysAuth && !e.AllSquash }

// nfsScript prints what the kernel NFS server exports now. etab is the
// table `exportfs -r` writes and mountd answers from; stopping the server
// empties it. Reading it changes nothing, unlike running exportfs (which
// creates lock files). The thread count says whether the server runs: a
// table left behind by a crash serves nothing.
const nfsScript = `t=
[ -r /proc/fs/nfsd/threads ] && t=$(cat /proc/fs/nfsd/threads 2>/dev/null)
echo "threads=$t"
if [ -e /var/lib/nfs/etab ]; then
  if [ -r /var/lib/nfs/etab ]; then sed 's/^/export|/' /var/lib/nfs/etab; else echo "unreadable"; fi
fi
echo "@@end"
`

// parseNFSExports reads nfsScript output. It returns an empty list when
// nothing is exported or the server is stopped, and nil with the reason
// when the table could not be read.
func parseNFSExports(s string) ([]NFSExport, string) {
	out := []NFSExport{}
	threads := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "@@end":
			if threads == "0" {
				return []NFSExport{}, ""
			}
			return out, ""
		case line == "unreadable":
			return nil, "cannot read /var/lib/nfs/etab"
		case strings.HasPrefix(line, "threads="):
			threads = strings.TrimSpace(strings.TrimPrefix(line, "threads="))
		case strings.HasPrefix(line, "export|"):
			if e, ok := parseEtabLine(strings.TrimPrefix(line, "export|")); ok {
				out = append(out, e)
			}
		}
	}
	return nil, "the export listing stopped early"
}

// parseEtabLine reads one etab line: "path<TAB>client(options)", with
// special characters in the path written as \ooo.
func parseEtabLine(line string) (NFSExport, bool) {
	p, rest, ok := strings.Cut(line, "\t")
	i := strings.LastIndexByte(rest, '(')
	if !ok || i <= 0 || !strings.HasSuffix(rest, ")") {
		return NFSExport{}, false
	}
	e := NFSExport{Path: unescapeOctal(p), Client: rest[:i]}
	setNFSOptions(&e, rest[i+1:len(rest)-1])
	return e, true
}

// setNFSOptions applies an etab option list. Options before the first
// sec= apply to every flavor; each sec=a:b starts that flavor list's own
// options (rw, squashing, secure). The sys flavor is the one that matters:
// with it, the client names the account. Without any sec=, it is sys.
func setNFSOptions(e *NFSExport, list string) {
	type opts struct {
		write, rootSquash, allSquash, anonRoot, insecure bool
	}
	apply := func(o *opts, t string) {
		switch t {
		case "rw":
			o.write = true
		case "ro":
			o.write = false
		case "root_squash":
			o.rootSquash = true
		case "no_root_squash":
			o.rootSquash = false
		case "all_squash":
			o.allSquash = true
		case "no_all_squash":
			o.allSquash = false
		case "insecure":
			o.insecure = true
		case "secure":
			o.insecure = false
		default:
			if v, ok := strings.CutPrefix(t, "anonuid="); ok {
				o.anonRoot = v == "0"
			}
		}
	}
	general := opts{rootSquash: true}
	var flavors [][]string
	var each []opts
	for _, t := range strings.Split(list, ",") {
		if v, ok := strings.CutPrefix(t, "sec="); ok {
			flavors = append(flavors, strings.Split(v, ":"))
			each = append(each, general)
			continue
		}
		if len(each) == 0 {
			apply(&general, t)
		} else {
			apply(&each[len(each)-1], t)
		}
	}
	o, sys := general, len(flavors) == 0
	for i, fl := range flavors {
		if !sys && contains(fl, "sys") {
			o, sys = each[i], true
		}
	}
	*e = NFSExport{Path: e.Path, Client: e.Client, Write: o.write, RootSquash: o.rootSquash,
		AllSquash: o.allSquash, AnonRoot: o.anonRoot, Insecure: o.insecure, SysAuth: sys}
}

// unescapeOctal turns \ooo escapes (\040 for a space) back into bytes.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
