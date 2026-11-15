package collect

import (
	"strings"
	"testing"
)

// FuzzParsers feeds the same text to every parser of host output, and to
// what runs on their results. Host output is whatever the host says: a
// parser must never panic on it. (A panic would fail that host's scan,
// see fleet.evaluate, but must not happen at all.) Run longer with
//
//	go test -run '^$' -fuzz FuzzParsers -fuzztime 2m ./internal/collect
func FuzzParsers(f *testing.F) {
	for _, s := range []string{
		doorsSample, sudoEnvSample, etabSample, getfaclSample,
		"", "\n", "@@end\n", "|||||", "acl|", "stat|0|0|755|directory|/\n@@end\n",
		"stat|-1|x|999999999999|socket|\n", "acl|/x|user:abc:rwx\nacl|/x|mask::\n@@end\n",
		"@@user root\nMatching Defaults entries for root on h:\n    env_keep+=\"LD_PRELOAD\n\n(root) SETENV: /usr/bin/true\n",
		"@@user u\nRunas and Command-specific defaults for u:\n    Defaults!/usr/bin/x, \"a b\" env_keep-=\n",
		"cap=pkg|0|cap_setuid=ep|/usr/bin/x\ncapsmore=x\n@@end\n", "cap=none|1000|=ep cap_setuid-p+e|/a b\n@@end\n",
		"trust|/etc/hosts.equiv||+|\n@@end\n", "suid=pkg /x\nsuidmore=-5\nww=d\n",
		"door|disk|/dev/sda\nstat|0|6|660|block special file|/dev/sda\n@@end\n",
		"@@cron system /etc/crontab\n* * * * root\n@@files x\n@@systemd\nExecStart={ path=\n@@end\n",
		"tcp LISTEN 0 4096 [::]:22 [::]:*\ntcp LISTEN 0 1 :::\n",
		"root:x:0:0::/root:/bin/sh\n:::::::\nbad\n",
		"web:x:abc:\nwheel:x:10:a,,b\n",
		"key|ssh|/root/.ssh/id|OPENSSH|SHA256:x\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		facts := &Facts{
			Passwd: []PasswdEntry{{Name: "root", Home: "/root", Shell: "/bin/sh"}, {Name: "bob", UID: 1000, GID: 1000, Home: "/home/bob"}},
			Groups: []GroupEntry{{Name: "root"}, {Name: "docker", GID: 999, Members: []string{"bob"}}},
		}
		parsePasswd(s)
		parseGroup(s)
		parseOSRelease(s)
		parseESM(s)
		parseSSHD(s)
		parseSudoers(s)
		parseShadow(s)
		parseSS(s)
		parseUpdates(s)
		parseKeyValues(s)
		parseReboot(s)
		parseAuthKeys(s)
		parseFirewall(s)
		parseFiles(s)
		parseContainers(s)
		parseDockerAPI(s)
		parseKeyLogins(s)
		parseLogStore(s)
		parseNFSExports(s)
		parsePAM(s)
		parsePolkit(s)
		parseListeners(s)
		parseProcNet(s, false)
		parseProcNet(s, true)
		parseRhosts(s)
		parseRootJobs(s)
		parsePaths(s)
		parseACLs(strings.Split(s, "\n"))
		parseScoped(s)
		parseSSHDMatch(s, map[string][]string{"permitrootlogin": {"yes"}}, map[string]string{})
		_, _ = complete(s)
		_ = count(s, "suidmore=")
		_ = lines(s)
		facts.parseDoors(s)
		facts.parseCredentials(s)
		facts.parsePrivateKeys(s)
		if caps, _ := parseFileCaps(s); caps != nil {
			for _, c := range caps {
				_ = c.Permitted("cap_setuid")
			}
		}
		_ = FileCap{Caps: s}.Permitted("cap_setuid")
		facts.SudoRights, facts.SudoDefaults = parseSudoRights(s)
		facts.markEnvEscapes()
		for u := range facts.SudoRights {
			facts.SudoAuthFor(u, "root", "ALL")
		}
		facts.RootDoors = facts.parseDoors(s)
		facts.RootDoorRoutes()
		loginJobs(facts)
	})
}
