package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755)
	file := func(p, content string, mode os.FileMode) {
		t.Helper()
		p = filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	secrets := []string{"s3cr3t", "XYZSECRET", "hunter2", "wp-pw", "ghp_tok", "netrcpw"}

	// alice's home is open: what every account can read counts.
	file("home/alice/.pgpass", "db.internal:5432:*:alice:s3cr3t\n", 0o644)
	file("home/alice/.my.cnf", "[client]\nuser=alice\n", 0o644) // no password: nothing to report
	file("home/alice/.aws/credentials", "[default]\naws_access_key_id = AKIA\naws_secret_access_key = XYZSECRET\n", 0o644)
	file("home/alice/.docker/config.json", `{"credsStore": "desktop"}`, 0o644) // a helper holds them
	file("home/alice/.netrc", "machine ftp.example.com login alice password netrcpw\n", 0o644)
	file("home/alice/.git-credentials", "https://alice:ghp_tok@github.com\n", 0o600) // only alice
	// bob's home is closed: nothing in it is readable by others.
	file("home/bob/.docker/config.json", `{"auths": {"r.example.com": {"auth": "Ym9iOnB3"}}}`, 0o644)
	os.Chmod(filepath.Join(dir, "home/bob"), 0o700)
	// Applications and a site.
	file("opt/app/.env", "APP_NAME=shop\nDB_PASSWORD=hunter2\n", 0o644)
	file("opt/plain/.env", "APP_NAME=docs\nDEBUG=true\n", 0o644)
	file("opt/empty/.env", "# DB_PASSWORD=\nAPI_KEY=\n", 0o644)
	file("var/www/site/wp-config.php", "<?php define('DB_PASSWORD', 'wp-pw');\n", 0o644)
	file("etc/mysql/debian.cnf", "[client]\npassword = s3cr3t\n", 0o600)

	uid := os.Getuid()
	passwd := "alice:x:" + strconv.Itoa(uid) + ":100::" + dir + "/home/alice:/bin/sh\n" +
		"bob:x:" + strconv.Itoa(uid) + ":100::" + dir + "/home/bob:/bin/sh\n"
	file("etc/passwd", passwd, 0o644)

	script := strings.NewReplacer("/etc/", dir+"/etc/", "/opt/", dir+"/opt/", "/srv/", dir+"/srv/", "/var/www/", dir+"/var/www/").Replace(credentialsScript)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Fatalf("secret %q left the host:\n%s", s, out)
		}
	}
	f := &Facts{Passwd: []PasswdEntry{{Name: "alice", UID: uid}}}
	got := f.parseCredentials(string(out))
	want := []Credential{
		{Path: dir + "/home/alice/.aws/credentials", What: "AWS credentials", Owner: "alice"},
		{Path: dir + "/home/alice/.netrc", What: "netrc with a password", Owner: "alice"},
		{Path: dir + "/home/alice/.pgpass", What: "PostgreSQL password file", Owner: "alice"},
		{Path: dir + "/opt/app/.env", What: "application secrets (.env)", Owner: "alice"},
		{Path: dir + "/var/www/site/wp-config.php", What: "WordPress database password", Owner: "alice"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v\noutput:\n%s", got, want, out)
	}
	if f.parseCredentials(strings.TrimSuffix(string(out), "@@end\n")) != nil {
		t.Error("output without @@end parsed")
	}
}
